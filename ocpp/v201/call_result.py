import warnings
from dataclasses import dataclass
from typing import Any, List, Optional

from ocpp.v201.datatypes import (
    CertificateHashDataChainType,
    ClearMonitoringResultType,
    CompositeScheduleType,
    CustomDataType,
    GetVariableResultType,
    IdTokenInfoType,
    MessageContentType,
    SetMonitoringResultType,
    SetVariableResultType,
    StatusInfoType,
)
from ocpp.v201.enums import (
    AuthorizeCertificateStatusType,
    CancelReservationStatusType,
    CertificateSignedStatusType,
    ChangeAvailabilityStatusType,
    ChargingProfileStatus,
    ClearCacheStatusType,
    ClearChargingProfileStatusType,
    ClearMessageStatusType,
    CustomerInformationStatusType,
    DataTransferStatusType,
    DeleteCertificateStatusType,
    DisplayMessageStatusType,
    GenericDeviceModelStatusType,
    GenericStatusType,
    GetCertificateStatusType,
    GetChargingProfileStatusType,
    GetDisplayMessagesStatusType,
    GetInstalledCertificateStatusType,
    InstallCertificateStatusType,
    Iso15118EVCertificateStatusType,
    LogStatusType,
    NotifyEVChargingNeedsStatusType,
    RegistrationStatusType,
    RequestStartStopStatusType,
    ReserveNowStatusType,
    ResetStatusType,
    SendLocalListStatusType,
    SetNetworkProfileStatusType,
    TriggerMessageStatusType,
    UnlockStatusType,
    UnpublishFirmwareStatusType,
    UpdateFirmwareStatusType,
)


@dataclass
class Authorize:
    id_token_info: IdTokenInfoType
    certificate_status: Optional[AuthorizeCertificateStatusType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class BootNotification:
    current_time: str
    interval: int
    status: RegistrationStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class CancelReservation:
    status: CancelReservationStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class CertificateSigned:
    status: CertificateSignedStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ChangeAvailability:
    status: ChangeAvailabilityStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearCache:
    status: ClearCacheStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearChargingProfile:
    status: ClearChargingProfileStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearDisplayMessage:
    status: ClearMessageStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearVariableMonitoring:
    clear_monitoring_result: List[ClearMonitoringResultType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class ClearedChargingLimit:
    custom_data: Optional[CustomDataType] = None


@dataclass
class CostUpdated:
    custom_data: Optional[CustomDataType] = None


@dataclass
class CustomerInformation:
    status: CustomerInformationStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class DataTransfer:
    status: DataTransferStatusType
    status_info: Optional[StatusInfoType] = None
    data: Optional[Any] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class DeleteCertificate:
    status: DeleteCertificateStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class FirmwareStatusNotification:
    custom_data: Optional[CustomDataType] = None


@dataclass
class Get15118EVCertificate:
    status: Iso15118EVCertificateStatusType
    exi_response: str
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetBaseReport:
    status: GenericDeviceModelStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetCertificateStatus:
    status: GetCertificateStatusType
    status_info: Optional[StatusInfoType] = None
    ocsp_result: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetChargingProfiles:
    status: GetChargingProfileStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetCompositeSchedule:
    status: GenericStatusType
    status_info: Optional[StatusInfoType] = None
    schedule: Optional[CompositeScheduleType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetDisplayMessages:
    status: GetDisplayMessagesStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetInstalledCertificateIds:
    status: GetInstalledCertificateStatusType
    status_info: Optional[StatusInfoType] = None
    certificate_hash_data_chain: Optional[CertificateHashDataChainType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetLocalListVersion:
    version_number: int
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetLog:
    status: LogStatusType
    status_info: Optional[StatusInfoType] = None
    filename: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetMonitoringReport:
    status: GenericDeviceModelStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetReport:
    status: GenericDeviceModelStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetTransactionStatus:
    messages_in_queue: bool
    ongoing_indicator: Optional[bool] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class GetVariables:
    get_variable_result: List[GetVariableResultType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class Heartbeat:
    current_time: str
    custom_data: Optional[CustomDataType] = None


@dataclass
class InstallCertificate:
    status: InstallCertificateStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class LogStatusNotification:
    custom_data: Optional[CustomDataType] = None


@dataclass
class MeterValues:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyChargingLimit:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyCustomerInformation:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyDisplayMessages:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEVChargingNeeds:
    status: NotifyEVChargingNeedsStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEVChargingSchedule:
    status: GenericStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyEvent:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyMonitoringReport:
    custom_data: Optional[CustomDataType] = None


@dataclass
class NotifyReport:
    custom_data: Optional[CustomDataType] = None


@dataclass
class PublishFirmware:
    status: GenericStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class PublishFirmwareStatusNotification:
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReportChargingProfiles:
    custom_data: Optional[CustomDataType] = None


@dataclass
class RequestStartTransaction:
    status: RequestStartStopStatusType
    status_info: Optional[StatusInfoType] = None
    transaction_id: Optional[str] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class RequestStopTransaction:
    status: RequestStartStopStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReservationStatusUpdate:
    custom_data: Optional[CustomDataType] = None


@dataclass
class ReserveNow:
    status: ReserveNowStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class Reset:
    status: ResetStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SecurityEventNotification:
    custom_data: Optional[CustomDataType] = None


@dataclass
class SendLocalList:
    status: SendLocalListStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetChargingProfile:
    status: ChargingProfileStatus
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetDisplayMessage:
    status: DisplayMessageStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetMonitoringBase:
    status: GenericDeviceModelStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetMonitoringLevel:
    status: GenericStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetNetworkProfile:
    status: SetNetworkProfileStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetVariableMonitoring:
    set_monitoring_result: List[SetMonitoringResultType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class SetVariables:
    set_variable_result: List[SetVariableResultType]
    custom_data: Optional[CustomDataType] = None


@dataclass
class SignCertificate:
    status: GenericStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class StatusNotification:
    custom_data: Optional[CustomDataType] = None


@dataclass
class TransactionEvent:
    total_cost: Optional[int] = None
    charging_priority: Optional[int] = None
    id_token_info: Optional[IdTokenInfoType] = None
    updated_personal_message: Optional[MessageContentType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class TriggerMessage:
    status: TriggerMessageStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class UnlockConnector:
    status: UnlockStatusType
    status_info: Optional[StatusInfoType] = None
    custom_data: Optional[CustomDataType] = None


@dataclass
class UnpublishFirmware:
    status: UnpublishFirmwareStatusType
    custom_data: Optional[CustomDataType] = None


@dataclass
class UpdateFirmware:
    status: UpdateFirmwareStatusType
    status_info: Optional[StatusInfoType] = None
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
