defmodule Crispkey.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Crispkey.Store.LocalState,
      Crispkey.Sync.Listener
    ]

    opts = [strategy: :one_for_one, name: Crispkey.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
