defmodule Crispkey do
  @moduledoc """
  GPG key synchronization across devices.
  """

  def data_dir do
    Application.get_env(:crispkey, :data_dir)
  end

  def gpg_homedir do
    Application.get_env(:crispkey, :gpg_homedir)
  end

  def device_id do
    case File.read(Path.join(data_dir(), "device_id")) do
      {:ok, id} -> String.trim(id)
      {:error, _} -> generate_device_id()
    end
  end

  defp generate_device_id do
    id = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    File.mkdir_p!(data_dir())
    File.write!(Path.join(data_dir(), "device_id"), id)
    id
  end
end
