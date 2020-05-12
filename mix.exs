defmodule Guardian.Token.Jwe.Mixfile do
  @moduledoc false
  use Mix.Project

  @version "0.2.0"
  @url "https://github.com/davepersing/guardian_jwe"
  @maintainers [
    "Dave Persing"
  ]

  def project do
    [
      name: "Guardian.Token.Jwe",
      app: :guardian_jwe,
      version: @version,
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      package: package(),
      source_url: @url,
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      maintainers: @maintainers,
      description: "JWE plugin for Guardian authentication framework",
      homepage_url: @url,
      docs: docs(),
      deps: deps()
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def docs do
    [
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:guardian, "~> 2.0"},
      # NOTE: plug is required because of the issue in guardian
      # https://github.com/ueberauth/guardian/issues/644
      {:plug, "~> 1.3.3 or ~> 1.4", optional: true},
      {:uuid, "~> 1.1"},
      {:credo, "~> 1.4", only: [:dev, :test]},
      {:ex_doc, "~> 0.22", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{github: @url},
      files: ~w(lib) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
