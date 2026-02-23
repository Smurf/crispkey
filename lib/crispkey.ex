defmodule Crispkey do
  @moduledoc """
  GPG key synchronization across devices.
  """

  @spec data_dir() :: String.t()
  def data_dir do
    Application.get_env(:crispkey, :data_dir)
  end

  @spec gpg_homedir() :: String.t()
  def gpg_homedir do
    Application.get_env(:crispkey, :gpg_homedir)
  end

  @spec device_id() :: String.t()
  def device_id do
    case File.read(Path.join(data_dir(), "device_id")) do
      {:ok, id} -> String.trim(id)
      {:error, _} -> generate_device_id()
    end
  end

  @spec generate_device_id() :: String.t()
  defp generate_device_id do
    id = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    File.mkdir_p!(data_dir())
    File.write!(Path.join(data_dir(), "device_id"), id)
    id
  end
end
