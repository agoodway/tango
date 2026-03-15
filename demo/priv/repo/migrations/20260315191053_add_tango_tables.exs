defmodule Demo.Repo.Migrations.AddTangoTables do
  use Ecto.Migration

  def up, do: Tango.Migration.up()
  def down, do: Tango.Migration.down()
end
