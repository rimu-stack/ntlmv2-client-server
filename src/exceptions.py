class UnknownDomainError(Exception):
    """Домен не зарегистрирован"""


class UnknownWorkstationError(Exception):
    """Рабочая станция не зарегистрирована"""


class UnknownUserError(Exception):
    """Пользователь не зарегистрирован"""


class InvalidNTLMSignatureError(Exception):
    """Сигнатура не является корректной"""


class InvalidNTLMMessageTypeError(Exception):
    """Тип сообщения не является корректным"""
