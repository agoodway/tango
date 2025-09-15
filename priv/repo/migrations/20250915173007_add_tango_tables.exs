defmodule Tango.TestRepo.Migrations.AddTangoTables do
  use Ecto.Migration

  def up do
    Tango.Migrations.up()
  end

  def down do
    Tango.Migrations.down()
  end
end
