defmodule Tango.TestRepo.Migrations.UpgradeTangoV3 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 3)
  def down, do: Tango.Migration.down(version: 2)
end
