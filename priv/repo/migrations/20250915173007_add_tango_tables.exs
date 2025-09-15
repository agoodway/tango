defmodule Tango.TestRepo.Migrations.AddTangoTables do
  use Ecto.Migration

  def up do
    Tango.Migration.up()
  end

  def down do
    Tango.Migration.down()
  end
end
