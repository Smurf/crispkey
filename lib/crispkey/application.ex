defmodule Crispkey.Application do
  @moduledoc """
  OTP Application callback module.
  """

  use Application

  @impl true
  @spec start(Application.start_type(), term()) :: {:ok, pid()} | {:error, term()}
  def start(_type, _args) do
    configure_runtime()

    children = [
      Crispkey.Store.LocalState,
      Crispkey.Vault.Manager
    ]

    opts = [strategy: :one_for_one, name: Crispkey.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @spec configure_runtime() :: :ok
  defp configure_runtime do
    if data_dir = System.get_env("CRISPKEY_DATA_DIR") do
      Application.put_env(:crispkey, :data_dir, data_dir, persistent: true)
    end

    if gpg_home = System.get_env("GNUPGHOME") do
      Application.put_env(:crispkey, :gpg_homedir, gpg_home, persistent: true)
    end

    :ok
  end
end
