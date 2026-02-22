import Config

if System.get_env("CRISPKEY_DATA_DIR") do
  config :crispkey, data_dir: System.get_env("CRISPKEY_DATA_DIR")
end

if System.get_env("GNUPGHOME") do
  config :crispkey, gpg_homedir: System.get_env("GNUPGHOME")
end
