NTLM_SIGNATURE = b'NTLMSSP\x00'


class MessageTypes:
    """Типы сообщений в протоколе NTLM"""
    
    NTLM_NEGOTIATE = 0x1
    "Сообщение для инициации сеанса аутентификации"
    
    NTLM_CHALLENGE = 0x2
    "Сообщение с вызовом (challenge) от сервера клиенту"
    
    NTLM_AUTHENTICATE = 0x3
    "Сообщение с данными аутентификации от клиента серверу"


class AvId:
    """
    16-битное беззнаковое целое число, определяющее тип информации в поле 
    значения для элемента AV_PAIR (Attribute-Value Pair) протокола NTLM.
    """

    # Константы для типов информации в AV_PAIR

    MSV_AV_EOL = 0x00
    """Конец списка атрибутов. Этот элемент сигнализирует конец списка AV_PAIR"""

    MSV_AV_NB_COMPUTER_NAME = 0x01
    """Имя компьютера (NetBIOS) клиента"""

    MSV_AV_NB_DOMAIN_NAME = 0x02
    """Имя домена (NetBIOS) клиента"""

    MSV_AV_DNS_COMPUTER_NAME = 0x03
    """Имя компьютера (DNS) клиента"""

    MSV_AV_DNS_DOMAIN_NAME = 0x04
    """Имя домена (DNS) клиента"""

    MSV_AV_DNS_TREE_NAME = 0x05
    """Имя доменного дерева (DNS) клиента"""

    MSV_AV_FLAGS = 0x06
    """Флаги, связанные с аутентификацией и авторизацией"""

    MSV_AV_TIMESTAMP = 0x07
    """Временная метка, используемая для предотвращения повторных атак"""

    MSV_AV_SINGLE_HOST = 0x08
    """Информация о единственном хосте, используемая в некоторых сценариях"""

    MSV_AV_TARGET_NAME = 0x09
    """Имя целевого сервера, к которому происходит аутентификация"""

    MSV_AV_CHANNEL_BINDINGS = 0x0a
    """Связывание каналов, используемое для защиты данных передачи"""


class AvFlags:
    """32-битное значение, указывающее конфигурацию сервера или клиента"""

    AUTHENTICATION_CONSTRAINED = 0x1
    """
    Ограничение аутентификации: используется для указания, что клиент должен быть 
    аутентифицирован только с использованием зашифрованных методов
    """

    MIC_PROVIDED = 0x2
    """Предоставление MIC (Message Integrity Code)"""

    UNTRUSTED_SPN_SOURCE = 0x4
    """Источник ненадежного SPN (Service Principal Name)"""


class NegotiateFlags:
    """
    Флаги определяют возможности клиента или сервера 
    NTLM, поддерживаемые отправителем
    """

    NTLMSSP_NEGOTIATE_56 = 0x80000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_RESERVED_R1 = 0x10000000
    NTLMSSP_RESERVED_R2 = 0x08000000
    NTLMSSP_RESERVED_R3 = 0x04000000
    NTLMSSP_NEGOTIATE_VERSION = 0x02000000
    NTLMSSP_RESERVED_R4 = 0x01000000
    NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NTLMSSP_RESERVED_R5 = 0x00200000
    NTLMSSP_NEGOTIATE_IDENTITY = 0x00100000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_RESERVED_R6 = 0x00040000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_RESERVED_R7 = 0x00004000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NTLMSSP_ANOYNMOUS = 0x00000800
    NTLMSSP_RESERVED_R8 = 0x00000400
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    NTLMSSP_RESERVED_R9 = 0x00000100
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_RESERVED_R10 = 0x00000008
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLMSSP_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001