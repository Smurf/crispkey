import Config

config :crispkey,
  gpg_homedir: Path.expand("~/.gnupg"),
  data_dir: Path.expand("~/.config/crispkey"),
  sync_port: 4829,
  discovery_port: 4830

config :logger, level: :info
