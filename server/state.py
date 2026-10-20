"""Values shared between modules that change while the server runs.

Always use them as `state.<name>` (e.g. `state.sc4mp_config`). A plain
`from server.state import sc4mp_config` would copy the value once, so later
changes made by other modules would not be seen.
"""


# Set from the config file by `update_config_constants()`
SC4MP_CONFIG_PATH = None
SC4MP_HOST = None
SC4MP_PORT = None
SC4MP_SERVER_ID = None
SC4MP_SERVER_NAME = None
SC4MP_SERVER_DESCRIPTION = None

# Set from the command line arguments in `main()`
sc4mp_server_path = "_SC4MP"

sc4mp_server_running = False

# Number of request handler threads currently running
sc4mp_request_threads = 0

# The names below are assigned while the server starts. They are only
# declared here (no value), so using one before it is set still raises an
# error, as it did when everything was in one file.
sc4mp_skip_update: bool
sc4mp_force_update: bool
sc4mp_nostart: bool
sc4mp_ui: object
sc4mp_server: object
sc4mp_config: object
sc4mp_system_tray_icon_manager: object
sc4mp_users_database_manager: object
sc4mp_clients_database_manager: object
sc4mp_regions_manager: object
sc4mp_backups_manager: object
sc4mp_filetables_manager: object
sc4mp_server_list: object
