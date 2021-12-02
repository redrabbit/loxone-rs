use serde::Deserialize;
use std::collections::HashMap;

use crate::loxapp3::{LoxoneUUID, LoxoneMutation, LoxoneSubControl};

#[derive(Debug, Deserialize)]
pub struct CentralLightController {
    pub details: CentralLightControllerDetails
}

#[derive(Debug, Deserialize)]
pub struct CentralLightControllerDetails {
    pub controls: Vec<CentralLightControllerControl>,
}

#[derive(Debug, Deserialize)]
pub struct CentralLightControllerControl {
    pub uuid: LoxoneUUID,
    pub id: u8
}

#[derive(Debug, Deserialize)]
 pub struct ClimateController {
    pub details: ClimateControllerDetails,
    pub states: ClimateControllerStates,
}

#[derive(Debug, Deserialize)]
pub struct ClimateControllerDetails {
    pub capabilities: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClimateControllerStates {
    pub controls: LoxoneUUID,
    pub current_mode: LoxoneUUID,
    pub auto_mode: LoxoneUUID,
    pub current_automatic: LoxoneUUID,
    pub temperature_boundary_info: LoxoneUUID,
    pub heating_temp_boundary: LoxoneUUID,
    pub cooling_temp_boundary: LoxoneUUID,
    pub actual_outdoor_temp: LoxoneUUID,
    pub average_outdoor_temp: LoxoneUUID,
    pub overwrite_reason: LoxoneUUID,
    pub info_text: LoxoneUUID,
    pub service_mode: LoxoneUUID,
    pub next_maintenance: LoxoneUUID,
    pub ventilation: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct ColorPicker {
    pub details: ColorPickerDetails,
    pub states: ColorPickerStates,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ColorPickerDetails {
    pub picker_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ColorPickerStates {
    pub color: LoxoneUUID,
    pub favorites: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct ColorPickerV2 {
    pub states: ColorPickerV2States,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ColorPickerV2States {
    pub color: LoxoneUUID,
    pub sequence: LoxoneUUID,
    pub sequence_color_idx: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct Dimmer {
    pub states: DimmerStates,
}

#[derive(Debug, Deserialize)]
pub struct DimmerStates {
    pub position: LoxoneUUID,
    pub min: LoxoneUUID,
    pub max: LoxoneUUID,
    pub step: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct InfoOnlyAnalog {
    pub details: InfoOnlyAnalogDetails,
    pub states: InfoOnlyStates
}

#[derive(Debug, Deserialize)]
pub struct InfoOnlyDigital {
    pub details: InfoOnlyAnalogDetails,
    pub states: InfoOnlyStates
}

#[derive(Debug, Deserialize)]
pub struct InfoOnlyAnalogDetails {
    pub format: String,
}

#[derive(Debug, Deserialize)]
pub struct InfoOnlyDigitalDetails {
    pub text: u8,
    pub image: LoxoneUUID,
    pub color: u8
}

#[derive(Debug, Deserialize)]
pub struct InfoOnlyStates {
    pub value: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct IRCV2Daytimer {
    pub details: IRCV2DaytimerDetails,
    pub states: IRCV2DaytimerStates,
}

#[derive(Debug, Deserialize)]
pub struct IRCV2DaytimerDetails {
    pub format: String,
    pub analog: bool
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IRCV2DaytimerStates {
    pub entries_and_default_value: LoxoneUUID,
    pub mode: LoxoneUUID,
    pub mode_list: LoxoneUUID,
    pub value: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IRoomControllerV2 {
    pub details: IRoomControllerV2Details,
    pub states: IRoomControllerV2States,
    pub sub_controls: HashMap<LoxoneUUID, LoxoneSubControl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IRoomControllerV2Details {
    pub format: String,
    pub timer_modes: Vec<IRoomControllerV2TimerMode>,
    pub connected_inputs: u32,
}

#[derive(Debug, Deserialize)]
pub struct IRoomControllerV2TimerMode {
    pub id: u8,
    pub name: String,
    pub description: String
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IRoomControllerV2States {
    pub active_mode: LoxoneUUID,
    pub operating_mode: LoxoneUUID,
    pub override_entries: LoxoneUUID,
    pub prepare_state: LoxoneUUID,
    pub override_reason: LoxoneUUID,
    pub temp_actual: LoxoneUUID,
    pub temp_target: LoxoneUUID,
    pub comfort_temperature: LoxoneUUID,
    pub comfort_tolerance: LoxoneUUID,
    pub absent_min_offset: LoxoneUUID,
    pub absent_max_offset: LoxoneUUID,
    pub frost_protect_temperature: LoxoneUUID,
    pub heat_protect_temperature: LoxoneUUID,
    pub comfort_temperature_offset: LoxoneUUID,
    pub open_window: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfcCodeTouchDetails {
    #[serde(default)]
    pub access_output: Vec<String>,
    pub place: Option<String>,
    #[serde(default)]
    pub two_factor_auth: bool,
}

#[derive(Debug, Deserialize)]
pub struct NfcCodeTouch {
    pub details: NfcCodeTouchDetails,
    pub states: NfcCodeTouchStates,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfcCodeTouchStates {
    pub history_date: LoxoneUUID,
    pub code_date: LoxoneUUID,
    pub device_state: LoxoneUUID,
    pub nfc_learn_result: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LightControllerV2 {
    pub details: LightControllerV2Details,
    pub states: LightControllerV2States,
    pub sub_controls: HashMap<LoxoneUUID, LoxoneSubControl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LightControllerV2Details {
    pub master_value: Option<LoxoneUUID>,
    pub master_color: Option<LoxoneUUID>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LightControllerV2States {
    pub active_moods: LoxoneUUID,
    pub mood_list: LoxoneUUID,
    pub favorite_moods: LoxoneUUID,
    pub additional_moods: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct Slider {
    pub details: SliderDetails,
    pub states: SliderStates
}

#[derive(Debug, Deserialize)]
pub struct SliderDetails {
    pub format: String,
    pub min: f32,
    pub max: f32,
    pub step: f32,
}

#[derive(Debug, Deserialize)]
pub struct SliderStates {
    pub value: LoxoneUUID,
    pub error: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmokeWaterAlarm {
    pub details: SmokeWaterAlarmDetails,
    pub states: SmokeWaterAlarmStates,
    pub sub_controls: HashMap<LoxoneUUID, LoxoneSubControl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmokeWaterAlarmDetails {
    pub has_acoustic_alarm: bool,
    pub available_alarms: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmokeWaterAlarmStates {
    pub next_level: LoxoneUUID,
    pub next_level_delay: LoxoneUUID,
    pub next_level_delay_total: LoxoneUUID,
    pub level: LoxoneUUID,
    pub sensors: LoxoneUUID,
    pub acoustic_alarm: LoxoneUUID,
    pub test_alarm: LoxoneUUID,
    pub alarm_cause: LoxoneUUID,
    pub start_time: LoxoneUUID,
    pub time_service_mode: LoxoneUUID,
    pub are_alarm_signals_off: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
pub struct Switch {
    pub states: SwitchStates
}

#[derive(Debug, Deserialize)]
pub struct SwitchStates {
    pub active: LoxoneUUID,
}

impl ColorPickerV2 {
    pub fn set_sequence(duration: u16, seq: &[LoxoneMutation], start_idx: i8) -> LoxoneMutation { format!("setSequence/{}/{}/{}", duration, seq.join("/"), start_idx) }
    pub fn set_brightness(brightness: u8) -> LoxoneMutation { format!("setBrightness/{}", brightness) }
    pub fn hsv(hue: u16, saturation: u16, brightness: u8) -> LoxoneMutation { format!("hsv({},{},{})", hue, saturation, brightness) }
    pub fn temp(brightness: u8, temperature: u16) -> LoxoneMutation { format!("temp({},{})", brightness, temperature) }
}

impl LightControllerV2 {
    pub fn add_mood(mood_id: u8) -> LoxoneMutation { format!("addMood/{}", mood_id) }
    pub fn add_to_favorite_mood(mood_id: u8) -> LoxoneMutation { format!("addToFavoriteMood/{}", mood_id) }
    pub fn change_to(mood_id: u8) -> LoxoneMutation { format!("changeTo/{}", mood_id) }
    pub fn learn(mood_id: u8, mood_name: &str) -> LoxoneMutation { format!("learn/{}/{}", mood_id, mood_name) }
    pub fn minus() -> LoxoneMutation { String::from("minus") }
    pub fn move_favorite_mood(mood_id: u8, index: u8) -> LoxoneMutation { format!("moveFavoriteMood/{}/{}", mood_id, index) }
    pub fn move_additional_mood(mood_id: u8, index: u8) -> LoxoneMutation { format!("moveAdditionalMood/{}/{}", mood_id, index) }
    pub fn move_mood(mood_id: u8, index: u8) -> LoxoneMutation { format!("moveMood/{}/{}", mood_id, index) }
    pub fn plus() -> LoxoneMutation { String::from("plus") }
    pub fn remove(mood_id: u8) -> LoxoneMutation { format!("delete/{}", mood_id) }
    pub fn remove_from_favorite_mood(mood_id: u8) -> LoxoneMutation { format!("removeFromFavoriteMood/{}", mood_id) }
    pub fn remove_mood(mood_id: u8) -> LoxoneMutation { format!("removeMood/{}", mood_id) }
}