from dishka import make_container

from ads_commons_beans import CommonsBeansProvider


def test_commons_beans_provider_builds_a_container() -> None:
    container = make_container(CommonsBeansProvider())
    container.close()
