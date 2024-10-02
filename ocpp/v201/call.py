import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ocpp.v201.datatypes import (
    AuthorizationData,
    CertificateHashDataType,
    ChargingLimitType,
    ChargingNeedsType,
    ChargingProfileCriterionType,
    ChargingProfileType,
    ChargingScheduleType,
    ChargingStationType,
    ComponentVariableType,
    CustomDataType,
    EVSEType,
    EventDataType,
    FirmwareType,
    GetVariableDataType,
    IdTokenType,
    LogParametersType,
    MessageInfoType,
    MeterValueType,
    MonitoringDataType,
    NetworkConnectionProfileType,
    OCSPRequestDataType,
    ReportDataType,
    SetMonitoringDataType,
    SetVariableDataType,
    TransactionType,
)

from ocpp.v201.enums import (
    BootReasonType,
    CertificateActionType,
    CertificateSigningUseType,
    ChargingLimitSourceType,
    ChargingRateUnitType,
    ComponentCriterionType,
    ConnectorStatusType,
    ConnectorType,
    FirmwareStatusType,
    GetCertificateIdUseType,
    InstallCertificateUseType,
    LogType,
    MessagePriorityType,
    MessageStateType,
    MessageTriggerType,
    MonitorBaseType,
    MonitoringCriterionType,
    OperationalStatusType,
    PublishFirmwareStatusType,
    ReportBaseType,
    ReservationUpdateStatusType,
    ResetType,
    TransactionEventType,
    TriggerReasonType,
    UpdateType,
    UploadLogStatusType,
)


@dataclass
class Authorize:
    id_token: IdTokenType
    certificate: Optional[str] = None
    iso15118_certificate_hash_data: Optional[List[OCSPRequestDataType]] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class BootNotification:
    charging_station: ChargingStationType
    reason: BootReasonType
    custom_data: Optional[CustomDataType] = None


@dataclass
class CancelReservation:
    reservation_id: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class CertificateSigned:
    certificate_chain: str
    certificate_type: Optional[CertificateSigningUseType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ChangeAvailability:
    operational_status: OperationalStatusType
    evse: Optional[EVSEType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearCache:
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearChargingProfile:
    charging_profile_id: Optional[int] = None
    charging_profile_criteria: Optional[Dict] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearDisplayMessage:
    id: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearVariableMonitoring:
    id: List[int]
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearedChargingLimit:
    charging_limit_source: str
    evse_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class CostUpdated:
    total_cost: float
    transaction_id: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class CustomerInformation:
    request_id: int
    report: bool
    clear: bool
    customer_certificate: Optional[CertificateHashDataType] = None
    id_token: Optional[IdTokenType] = None
    customer_identifier: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class DataTransfer:
    vendor_id: str
    message_id: Optional[str] = None
    data: Optional[Any] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class DeleteCertificate:
    certificate_hash_data: CertificateHashDataType
    custom_data: Optional[CustomDataType] = None


@dataclass
class FirmwareStatusNotification:
    status: FirmwareStatusType
    request_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class Get15118EVCertificate:
    iso15118_schema_version: str
    action: CertificateActionType
    exi_request: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetBaseReport:
    request_id: int
    report_base: ReportBaseType
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetCertificateStatus:
    ocsp_request_data: OCSPRequestDataType
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetChargingProfiles:
    request_id: int
    charging_profile: ChargingProfileCriterionType
    evse_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetCompositeSchedule:
    duration: int
    evse_id: int
    charging_rate_unit: Optional[ChargingRateUnitType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetDisplayMessages:
    request_id: int
    id: Optional[List[int]] = None
    priority: Optional[MessagePriorityType] = None
    state: Optional[MessageStateType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetInstalledCertificateIds:
    certificate_type: Optional[List[GetCertificateIdUseType]] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetLocalListVersion:
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetLog:
    log: LogParametersType
    log_type: LogType
    request_id: int
    retries: Optional[int] = None
    retry_interval: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetMonitoringReport:
    request_id: int
    component_variable: Optional[List[ComponentVariableType]] = None
    monitoring_criteria: Optional[List[MonitoringCriterionType]] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetReport:
    request_id: int
    component_variable: Optional[List[ComponentVariableType]] = None
    component_criteria: Optional[List[ComponentCriterionType]] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetTransactionStatus:
    transaction_id: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetVariables:
    get_variable_data: List[GetVariableDataType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class Heartbeat:
    custom_data: Optional[CustomDataType] = None


@dataclass
class InstallCertificate:
    certificate_type: InstallCertificateUseType
    certificate: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class LogStatusNotification:
    status: UploadLogStatusType
    request_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class MeterValues:
    evse_id: int
    meter_value: List[MeterValueType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyChargingLimit:
    charging_limit: ChargingLimitType
    charging_schedule: Optional[List[ChargingScheduleType]] = None
    evse_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyCustomerInformation:
    data: str
    seq_no: int
    generated_at: str
    request_id: int
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyDisplayMessages:
    request_id: int
    message_info: Optional[List[MessageInfoType]] = None
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEVChargingNeeds:
    charging_needs: ChargingNeedsType
    evse_id: int
    max_schedule_tuples: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEVChargingSchedule:
    time_base: str
    charging_schedule: ChargingScheduleType
    evse_id: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEvent:
    generated_at: str
    seq_no: int
    event_data: List[EventDataType]
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyMonitoringReport:
    request_id: int
    seq_no: int
    generated_at: str
    monitor: Optional[List[MonitoringDataType]] = None
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyReport:
    request_id: int
    generated_at: str
    seq_no: int
    report_data: Optional[List[ReportDataType]] = None
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class PublishFirmware:
    location: str
    checksum: str
    request_id: int
    retries: Optional[int] = None
    retry_interval: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class PublishFirmwareStatusNotification:
    status: PublishFirmwareStatusType
    location: Optional[List[str]] = None
    request_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReportChargingProfiles:
    request_id: int
    charging_limit_source: ChargingLimitSourceType
    charging_profile: List[ChargingProfileType]
    evse_id: int
    tbc: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class RequestStartTransaction:
    id_token: IdTokenType
    remote_start_id: int
    evse_id: Optional[int] = None
    group_id_token: Optional[IdTokenType] = None
    charging_profile: Optional[ChargingProfileType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class RequestStopTransaction:
    transaction_id: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReservationStatusUpdate:
    reservation_id: int
    reservation_update_status: ReservationUpdateStatusType
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReserveNow:
    id: int
    expiry_date_time: str
    id_token: IdTokenType
    connector_type: Optional[ConnectorType] = None
    evse_id: Optional[int] = None
    group_id_token: Optional[IdTokenType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class Reset:
    type: ResetType
    evse_id: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SecurityEventNotification:
    type: str
    timestamp: str
    tech_info: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SendLocalList:
    version_number: int
    update_type: UpdateType
    local_authorization_list: Optional[List[AuthorizationData]] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetChargingProfile:
    evse_id: int
    charging_profile: ChargingProfileType
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetDisplayMessage:
    message: MessageInfoType
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetMonitoringBase:
    monitoring_base: MonitorBaseType
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetMonitoringLevel:
    severity: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetNetworkProfile:
    configuration_slot: int
    connection_data: NetworkConnectionProfileType
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetVariableMonitoring:
    set_monitoring_data: List[SetMonitoringDataType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetVariables:
    set_variable_data: List[SetVariableDataType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class SignCertificate:
    csr: str
    certificate_type: Optional[CertificateSigningUseType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class StatusNotification:
    timestamp: str
    connector_status: ConnectorStatusType
    evse_id: int
    connector_id: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class TransactionEvent:
    event_type: TransactionEventType
    timestamp: str
    trigger_reason: TriggerReasonType
    seq_no: int
    transaction_info: TransactionType
    meter_value: Optional[List[MeterValueType]] = None
    offline: Optional[bool] = None
    number_of_phases_used: Optional[int] = None
    cable_max_current: Optional[int] = None
    reservation_id: Optional[int] = None
    evse: Optional[EVSEType] = None
    id_token: Optional[IdTokenType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class TriggerMessage:
    requested_message: MessageTriggerType
    evse: Optional[EVSEType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class UnlockConnector:
    evse_id: int
    connector_id: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class UnpublishFirmware:
    checksum: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class UpdateFirmware:
    request_id: int
    firmware: FirmwareType
    retries: Optional[int] = None
    retry_interval: Optional[int] = None
    custom_data: Optional[CustomDataType] = None


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class AuthorizePayload(Authorize):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class BootNotificationPayload(BootNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class CancelReservationPayload(CancelReservation):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class CertificateSignedPayload(CertificateSigned):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ChangeAvailabilityPayload(ChangeAvailability):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ClearCachePayload(ClearCache):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ClearChargingProfilePayload(ClearChargingProfile):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ClearDisplayMessagePayload(ClearDisplayMessage):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ClearVariableMonitoringPayload(ClearVariableMonitoring):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ClearedChargingLimitPayload(ClearedChargingLimit):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class CostUpdatedPayload(CostUpdated):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class CustomerInformationPayload(CustomerInformation):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class DataTransferPayload(DataTransfer):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class DeleteCertificatePayload(DeleteCertificate):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class FirmwareStatusNotificationPayload(FirmwareStatusNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class Get15118EVCertificatePayload(Get15118EVCertificate):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetBaseReportPayload(GetBaseReport):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetCertificateStatusPayload(GetCertificateStatus):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetChargingProfilesPayload(GetChargingProfiles):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetCompositeSchedulePayload(GetCompositeSchedule):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetDisplayMessagesPayload(GetDisplayMessages):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetInstalledCertificateIdsPayload(GetInstalledCertificateIds):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetLocalListVersionPayload(GetLocalListVersion):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetLogPayload(GetLog):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetMonitoringReportPayload(GetMonitoringReport):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetReportPayload(GetReport):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetTransactionStatusPayload(GetTransactionStatus):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class GetVariablesPayload(GetVariables):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class HeartbeatPayload(Heartbeat):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class InstallCertificatePayload(InstallCertificate):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class LogStatusNotificationPayload(LogStatusNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class MeterValuesPayload(MeterValues):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyChargingLimitPayload(NotifyChargingLimit):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyCustomerInformationPayload(NotifyCustomerInformation):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyDisplayMessagesPayload(NotifyDisplayMessages):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyEVChargingNeedsPayload(NotifyEVChargingNeeds):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyEVChargingSchedulePayload(NotifyEVChargingSchedule):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyEventPayload(NotifyEvent):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyMonitoringReportPayload(NotifyMonitoringReport):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class NotifyReportPayload(NotifyReport):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class PublishFirmwarePayload(PublishFirmware):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class PublishFirmwareStatusNotificationPayload(PublishFirmwareStatusNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ReportChargingProfilesPayload(ReportChargingProfiles):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class RequestStartTransactionPayload(RequestStartTransaction):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class RequestStopTransactionPayload(RequestStopTransaction):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ReservationStatusUpdatePayload(ReservationStatusUpdate):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ReserveNowPayload(ReserveNow):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class ResetPayload(Reset):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SecurityEventNotificationPayload(SecurityEventNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SendLocalListPayload(SendLocalList):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetChargingProfilePayload(SetChargingProfile):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetDisplayMessagePayload(SetDisplayMessage):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetMonitoringBasePayload(SetMonitoringBase):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetMonitoringLevelPayload(SetMonitoringLevel):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetNetworkProfilePayload(SetNetworkProfile):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetVariableMonitoringPayload(SetVariableMonitoring):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SetVariablesPayload(SetVariables):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class SignCertificatePayload(SignCertificate):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class StatusNotificationPayload(StatusNotification):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class TransactionEventPayload(TransactionEvent):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class TriggerMessagePayload(TriggerMessage):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class UnlockConnectorPayload(UnlockConnector):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class UnpublishFirmwarePayload(UnpublishFirmware):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )


# Dataclass soon to be deprecated use equal class name without the suffix 'Payload'
@dataclass
class UpdateFirmwarePayload(UpdateFirmware):
    def __post_init__(self):
        warnings.warn(
            (
                __class__.__name__
                + " is deprecated, use instead "
                + __class__.__mro__[1].__name__
            )
        )
