defmodule Tango.TestRepo.Migrations.UpgradeTangoV4 do
  use Ecto.Migration

  def up, do: Tango.Migration.up(version: 4)
  def down, do: Tango.Migration.down(version: 3)
end
