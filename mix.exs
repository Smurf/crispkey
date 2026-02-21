defmodule Crispkey.MixProject do
  use Mix.Project

  def project do
    [
      app: :crispkey,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: [main_module: Crispkey.CLI],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Crispkey.Application, []}
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:ranch, "~> 2.1"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
