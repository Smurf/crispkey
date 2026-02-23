import Config

config :crispkey,
  gpg_homedir: System.get_env("GNUPGHOME") || Path.expand("~/.gnupg"),
  data_dir: System.get_env("CRISPKEY_DATA_DIR") || Path.expand("~/.config/crispkey"),
  sync_port: 4829,
  discovery_port: 4830

config :logger, level: :info
