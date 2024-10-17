from dynaconf import Dynaconf

settings = Dynaconf(
    envvar_prefix="EYEON_",
    settings_files=["eyeon_settings.toml"],
)
