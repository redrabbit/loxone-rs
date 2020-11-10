use serde::Deserialize;
use std::collections::HashMap;

pub mod controllers;

use controllers::*;

/// Universally Unique Identifier (UUID).
pub type LoxoneUUID = String;

/// Command description.
pub type LoxoneMutation = String;

/// State that may change over time. 
#[derive(Debug)]
pub enum LoxoneState {
    Value(f64),
    Text(String, LoxoneUUID),
    Daytimer(Vec<LoxoneDaytimerEntry>, f64),
    Weather(Vec<LoxoneWeatherEntry>, u32),
}

/// Miniserver global configuration aka. “structure file”.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneApp3 {
 // TODO autopilot
    pub cats: HashMap<LoxoneUUID, LoxoneCategory>,
    pub controls: HashMap<LoxoneUUID, LoxoneControl>,
    pub global_states: LoxoneGlobalStates,
    pub last_modified: String,
    pub message_center: HashMap<LoxoneUUID, LoxoneMessage>,
    pub ms_info: LoxoneMiniserverInfo,
    pub operating_modes: HashMap<i8, String>,
    pub rooms: HashMap<LoxoneUUID, LoxoneRoom>,
    pub times: HashMap<String, LoxoneTime>,
 // TODO weather_server
}

/// Category that is used to group controls logically.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneCategory {
    pub color: String,
    pub image: String,
    pub is_favorite: bool,
    pub name: String,
    pub r#type: String,
    pub uuid: LoxoneUUID,
}

/// Control that is used to represent sensors and actuators.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneControl {
    pub cat: Option<LoxoneUUID>,
    #[serde(flatten)]
    pub controller: LoxoneController,
    pub default_icon: Option<String>,
    pub default_rating: u8,
 // TODO has_control_notes
    pub is_favorite: bool,
    pub is_secured: bool,
    pub name: String,
 // TODO restriction
    pub room: Option<LoxoneUUID>,
 // TODO secured_details
 // TODO statistics
    pub uuid_action: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneSubControl {
    #[serde(flatten)]
    pub controller: LoxoneController,
    pub default_rating: u8,
 // TODO has_control_notes
    pub is_favorite: bool,
    pub is_secured: bool,
    pub name: String,
 // TODO restriction
 // TODO secured_details
 // TODO statistics
    pub uuid_action: LoxoneUUID,
}

/// Global states that affect the whole Miniserver.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneGlobalStates {
    pub sunset: LoxoneUUID,
    pub sunrise: LoxoneUUID,
    pub fav_color_sequences: LoxoneUUID,
    pub fav_colors: LoxoneUUID,
    pub notifications: LoxoneUUID,
    pub miniserver_time: LoxoneUUID,
    pub live_search: LoxoneUUID,
    pub has_internet: LoxoneUUID,
    pub operating_mode: LoxoneUUID,
    pub planned_tasks: LoxoneUUID,
    pub past_tasks: LoxoneUUID,
    pub modifications: LoxoneUUID,
    pub user_settings: LoxoneUUID,
}

/// System status message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneMessage {
    pub name: String,
    pub uuid_action: LoxoneUUID,
    pub states: HashMap<String, LoxoneUUID>,
}

/// Static informations on the Miniserver and it’s configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneMiniserverInfo {
    pub serial_nr: String,
    pub ms_name: String,
    pub project_name: String,
    pub local_url: String,
    pub remote_url: String,
    pub temp_unit: u8,
    pub currency: String,
    pub square_measure: String,
    pub location: String,
    pub heat_period_start: String,
    pub heat_period_end: String,
    pub cool_period_start: String,
    pub cool_period_end: String,
    pub cat_title: String,
    pub room_title: String,
    pub miniserver_type: u8,
    pub current_user: LoxoneUser,
    pub device_monitor: LoxoneUUID,
    pub language_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneUser {
    pub uuid: LoxoneUUID,
    pub name: String,
    pub is_admin: bool,
    pub change_password: bool,
    pub user_rights: u16,
}

/// Room that is used to group controls based on their location.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneRoom {
    pub uuid: LoxoneUUID,
    pub name: String,
    pub image: String,
    pub default_rating: u8,
    pub is_favorite: bool,
    pub r#type: u8,
}

#[derive(Debug, Deserialize)]
pub struct LoxoneTime {
    pub id: u16,
    pub name: String,
    pub analog: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LoxoneController {
    AalEmergency,
    AalSmartAlarm,
    Alarm,
    AlarmChain,
    AlarmClock,
    AudioZone,
    CarCharger,
    CentralAlarm,
    CentralAudioZone,
    CentralGate,
    CentralJalousie,
    CentralLightController(CentralLightController),
    ClimateController(ClimateController),
    ColorPicker(ColorPicker),
    ColorPickerV2(ColorPickerV2),
    Daytimer,
    Dimmer(Dimmer),
    FanController,
    Fronius,
    Gate,
    Heatmixer,
    Hourcounter,
    InfoOnlyAnalog(InfoOnlyAnalog),
    InfoOnlyDigital(InfoOnlyDigital),
    IntelligentRoomControllerv2,
    IntelligentRoomControllerIntercom,
    IRCV2Daytimer(IRCV2Daytimer),
    IRoomController,
    IRoomControllerV2(IRoomControllerV2), 
    Jalousie,
    NfcCodeTouch(NfcCodeTouch),
    LightController,
    LightControllerV2(LightControllerV2),
    LightsceneRGB,
    MailBox,
    Meter,
    PoolController,
    Pushbutton,
    Radio,
    Remote,
    Sauna,
    Slider(Slider),
    SmokeAlarm(SmokeWaterAlarm),
    WaterAlarm(SmokeWaterAlarm),
    SolarPumpController,
    SteakThermo,
    Switch(Switch),
    SystemScheme,
    TextState,
    TextInput,
    TimedSwitch,
    Tracker,
    UpDownLeftRight,
    ValueSelector,
    Ventilation,
    Webpage,
    Window,
    WindowMonitor,
}

/// Day timer event entry.
#[derive(Debug)]
pub struct LoxoneDaytimerEntry {
    pub mode: i32,
    pub from: i32,
    pub to: i32,
    pub need_activate: i32,
    pub value: f64,
}

/// Weather event entry.
#[derive(Debug)]
pub struct LoxoneWeatherEntry {
    pub timestamp: i32,
    pub weather_type: i32,
    pub wind_direction: i32,
    pub solar_radiation: i32,
    pub relative_humidity: i32,
    pub temperature: f64,
    pub perceived_temperature: f64,
    pub dew_point: f64,
    pub precipitation: f64,
    pub wind_speed: f64,
    pub barometic_pressure: f64,
}