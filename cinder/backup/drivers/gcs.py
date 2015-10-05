# Copyright 2015 Red Hat, Inc. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Cinder backup service using Google Cloud Service (GCS) as storage backend

This driver supports backing up up volumes of any type to a Google Cloud
Service object store.

It allows normal backups as well as incremental backups.

Operations are authenticated via OAuth2 using a Service Account[1] and 2 types
of keys are suported by the driver as `backup_gcs_private_key_file` option,
.pem and .json files.  If a .pem key file is used then backup_gcs_client_email
options must be configured as well.

If no bucket name is defined default will be used: <project_id>.appspot.com

To use development storage we must change `backup_gcs_authorization_url` to
https://www.googleapis.com/auth/devstorage.read_write or
https://www.googleapis.com/auth/devstorage.full_control

Some options are only required/used if the bucket doesn't already exist:
- backup_gcs_bucket_location
- backup_gcs_bucket_storage_class
- backup_gcs_bucket_default_acl
- backup_gcs_project_id

[1]: https://cloud.google.com/storage/docs/authentication?#service_accounts
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from oslo_utils import units

import gcs_client as gcs

from cinder.backup import chunkeddriver
from cinder import exception
from cinder.i18n import _
from cinder import utils


LOG = logging.getLogger(__name__)

gcs_backup_service_opts = [
    # Authentication options
    cfg.StrOpt('backup_gcs_private_key_file',
               required=True,
               help='File that contains service private key (JSON or PEM)'),
    cfg.StrOpt('backup_gcs_client_email',
               default=None,
               help='Client email used for authentication when using PEM key'),
    cfg.StrOpt('backup_gcs_cert_scope',
               default='WRITER',
               help='Scope for the credentials. Default is WRITER, but can '
                    'also be OWNER.'),

    # File naming related options
    cfg.StrOpt('backup_gcs_name_template',
               default='volume_%(vol_id)s/%(timestamp)s/'
               'az_%(az)s_backup_%(backup_id)s',
               help='Template used for naming backups to add to the backup '
               'filename'),

    # Bucket related options
    cfg.StrOpt('backup_gcs_project_id',
               default=None,
               help="Bucket's project id, used on bucket creation if it "
                    "doesn't already exist."),
    cfg.StrOpt('backup_gcs_bucket',
               default=None,
               help='Bucket name to store backups in. If not defined default '
               'wil be <project_id>.appspot.com'),
    cfg.StrOpt('backup_gcs_bucket_location',
               default='US',
               help="Bucket's location, used on bucket creation if it doesn't "
                    "already exist"),
    cfg.StrOpt('backup_gcs_bucket_storage_class',
               default=None,
               help="Bucket's storage class, used on bucket creation if it "
                    "doesn't already exist. Acceptable values are STANDARD, "
                    "NEARLINE and DURABLE_REDUCED_AVAILABILITY.  Default is "
                    "Google's default (NEARLINE)"),
    cfg.StrOpt('backup_gcs_bucket_default_acl',
               default='projectPrivate',
               help="Bucket's default ACL, used on bucket creation if it "
               "doesn't already exist. Acceptable values are projectPrivate "
               "private, publicReadWrite. Default is projectPrivate."),

    # Retry configuration options when receiving transient errors from GCS
    cfg.IntOpt('backup_gcs_max_retries',
               default=6,
               help='Max number of times to retry. Set to 0 for no retries.'),
    cfg.FloatOpt('backup_gcs_retry_initial_delay',
                 default=1,
                 help='Seconds to delay the first retry'),
    cfg.FloatOpt('backup_gcs_retry_max_backoff',
                 default=32.0,
                 help='Max total seconds to wait between retries.'),
    cfg.FloatOpt('backup_gcs_retry_backoff_factor',
                 default=2.0,
                 help='Exponential backoff multiplier for retries'),
    cfg.BoolOpt('backup_gcs_randomize_retry_wait',
                help='Whether to use randomization of the delay time to avoid '
                     'synchronized waves.'),


    # Object and Chunks options
    cfg.IntOpt('backup_gcs_object_size',
               default=52428800,
               help='The size in bytes of GCS backup objects (chunks)'),
    cfg.IntOpt('backup_gcs_block_size',
               default=32768,
               help='The size in bytes that changes are tracked '
                    'for incremental backups. backup_gcs_object_size '
                    'has to be multiple of backup_gcs_block_size.'),

    cfg.BoolOpt('backup_gcs_enable_progress_timer',
                default=True,
                help='Enable or Disable the timer to send the periodic '
                     'progress notifications to Ceilometer when backing '
                     'up the volume to the GCS backend storage. The '
                     'default value is True to enable the timer.'),

    cfg.IntOpt('backup_gcs_http_chunk_size',
               default=2 * units.Mi,
               help='Size of HTTP data chunks sent and received from GCS. '
                    'Default 2MB.'),
]

CONF = cfg.CONF
CONF.register_opts(gcs_backup_service_opts)


class GCSBackupDriver(chunkeddriver.ChunkedBackupDriver):
    """Provides backup, restore and delete of backup objects within GCS."""

    def __init__(self, context, db_driver=None):
        chunk_size_bytes = CONF.backup_gcs_object_size
        sha_block_size_bytes = CONF.backup_gcs_block_size

        backup_default_container = utils.convert_str(
            CONF.backup_gcs_bucket or self.project.default_bucket_name)
        enable_progress_timer = CONF.backup_gcs_enable_progress_timer
        super(GCSBackupDriver, self).__init__(context, chunk_size_bytes,
                                              sha_block_size_bytes,
                                              backup_default_container,
                                              enable_progress_timer,
                                              db_driver)

        self.credentials = gcs.Credentials(CONF.backup_gcs_private_key_file,
                                           CONF.backup_gcs_client_email,
                                           CONF.backup_gcs_cert_scope)

        retry_params = gcs.RetryParams(
            max_retries=CONF.backup_gcs_max_retries,
            initial_delay=CONF.backup_gcs_retry_initial_delay,
            max_backoff=CONF.backup_gcs_retry_max_backoff,
            backoff_factor=CONF.backup_gcs_retry_backoff_factor,
            randomize=CONF.backup_gcs_randomize_retry_wait)
        gcs.RetryParams.set_default(retry_params)

    def put_container(self, container):
        """Create the bucket if needed. No failure if it pre-exists."""
        # Check for bucket's existence
        bucket = gcs.Bucket(container, self.credentials)
        if bucket.exists():
            return

        # Create it if it doesn't exist
        try:
            project = gcs.Project(CONF.backup_gcs_project_id, self.credentials)
            project.create_bucket(
                name=container,
                location=CONF.backup_gcs_bucket_location,
                storage_class=CONF.backup_gcs_bucket_storage_class,
                predefined_acl=CONF.backup_gcs_bucket_default_acl)
        except gcs.errors.Error as exc:
            msg = (_('Error creating bucket %(bucket)s: %(error)s') %
                   {'bucket': container, 'error': exc})
            LOG.error(msg)
            raise exception.GCSError(msg)

    def get_container_entries(self, container, prefix):
        """Get bucket entry names"""
        bucket = gcs.Bucket(container, self.credentials)
        try:
            return tuple(o.name for o in bucket.list(prefix=prefix))
        except gcs.errors.Error as exc:
            msg = (_('Error getting entries from bucket %(bucket)s: '
                     '%(error)s') % {'bucket': container, 'error': exc})
            LOG.error(msg)
            raise exception.GCSError(msg)

    def get_object_writer(self, container, object_name, extra_metadata=None):
        """Return a writer object.

        Returns a writer object that stores a chunk of volume data in a
        GCS object store.
        """
        try:
            return gcs.GCSObjFile(container, object_name, self.credentials,
                                  'w',
                                  chunksize=CONF.backup_gcs_http_chunk_size)
        except gcs.errors.Error as exc:
            msg = (_('Error creating file %(file)s in bucket %(bucket)s: '
                     '%(error)s') %
                   {'file': object_name, 'bucket': container, 'error': exc})
            LOG.error(msg)
            raise exception.GCSError(msg)

    def get_object_reader(self, container, object_name, extra_metadata=None):
        """Return reader object.

        Returns a reader object that retrieves a chunk of backed-up volume data
        from a GCS object store.
        """
        try:
            return gcs.GCSObjFile(container, object_name, self.credentials,
                                  'r', CONF.backup_gcs_http_chunk_size)
        except gcs.errors.Error as exc:
            msg = (_('Error opening file %(file)s in bucket %(bucket)s: '
                     '%(error)s') %
                   {'file': object_name, 'bucket': container, 'error': exc})
            LOG.error(msg)
            raise exception.GCSError(msg)

    def delete_object(self, container, object_name):
        """Deletes a backup object from a GCS object store."""
        try:
            obj = gcs.Object(container, object_name,
                             credentials=self.credentials)
            obj.delete()
        except gcs.errors.Error as exc:
            msg = (_('Error deleting file %(file)s in bucket %(bucket)s: '
                     '%(error)s') %
                   {'file': object_name, 'bucket': container, 'error': exc})
            LOG.error(msg)
            raise exception.GCSError(msg)

    def _generate_object_name_prefix(self, backup):
        """Generates a GCS backup object name prefix."""
        placeholders = {
            'az': self.az,
            'backup_id': backup['id'],
            'timestamp': timeutils.utcnow().strftime("%Y%m%d%H%M%S"),
            'vol_id': backup['volume_id']}

        prefix = CONF.backup_gcs_name_template % placeholders
        LOG.debug('generate_object_name_prefix: %s', prefix)
        return prefix

    def update_container_name(self, backup, container):
        """Use the container name as provided - don't update."""
        return container

    def get_extra_metadata(self, backup, volume):
        """GCS driver does not use any extra metadata."""
        return None


def get_backup_driver(context):
    return GCSBackupDriver(context)
