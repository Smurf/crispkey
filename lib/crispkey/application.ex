defmodule Crispkey.Application do
  use Application

  @impl true
  def start(_type, _args) do
    configure_runtime()

    children = [
      Crispkey.Store.LocalState
    ]

    opts = [strategy: :one_for_one, name: Crispkey.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp configure_runtime do
    if data_dir = System.get_env("CRISPKEY_DATA_DIR") do
      Application.put_env(:crispkey, :data_dir, data_dir, persistent: true)
    end

    if gpg_home = System.get_env("GNUPGHOME") do
      Application.put_env(:crispkey, :gpg_homedir, gpg_home, persistent: true)
    end
  end
end
