use serde::Deserialize;
use std::collections::HashMap;

use crate::LoxoneUUID;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Miniserver global configuration aka. “structure file”.
pub struct LoxoneApp3 {
    autopilot: HashMap<LoxoneUUID, LoxoneAutopilot>,
    cats: HashMap<LoxoneUUID, LoxoneCategory>,
    controls: HashMap<LoxoneUUID, LoxoneControl>,
    global_states: LoxoneGlobalStates,
    last_modified: String,
    message_center: HashMap<LoxoneUUID, LoxoneMessageCenter>,
    ms_info: LoxoneMiniserverInfo,
    operating_modes: HashMap<i8, String>,
    rooms: HashMap<LoxoneUUID, LoxoneRoom>,
    times: HashMap<String, LoxoneTime>,
    // TODO weatherServer
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneAutopilot {
    name: String,
    states: HashMap<String, LoxoneUUID>,
    uuid_action: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneCategory {
    color: String,
    image: String,
    is_favorite: bool,
    name: String,
    r#type: String,
    uuid: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneControl {
    cat: LoxoneUUID,
    default_icon: Option<String>,
    default_rating: u8,
    details: HashMap<String, serde_json::Value>,
    is_favorite: bool,
    is_secured: bool,
    name: String,
    room: LoxoneUUID,
    states: Option<HashMap<String, LoxoneUUID>>,
    sub_controls: Option<HashMap<LoxoneUUID, LoxoneSubControl>>,
    r#type: String,
    uuid_action: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneSubControl {
    default_rating: u8,
    details: Option<HashMap<String, serde_json::Value>>,
    is_favorite: bool,
    is_secured: bool,
    name: String,
    states: HashMap<String, LoxoneUUID>,
    r#type: String,
    uuid_action: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneGlobalStates {
    sunset: LoxoneUUID,
    sunrise: LoxoneUUID,
    fav_color_sequences: LoxoneUUID,
    fav_colors: LoxoneUUID,
    notifications: LoxoneUUID,
    miniserver_time: LoxoneUUID,
    live_search: LoxoneUUID,
    has_internet: LoxoneUUID,
    operating_mode: LoxoneUUID,
    planned_tasks: LoxoneUUID,
    past_tasks: LoxoneUUID,
    modifications: LoxoneUUID,
    user_settings: LoxoneUUID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneMessageCenter {
    name: String,
    uuid_action: LoxoneUUID,
    states: HashMap<String, LoxoneUUID>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneMiniserverInfo {
    serial_nr: String,
    ms_name: String,
    project_name: String,
    local_url: String,
    remote_url: String,
    temp_unit: u8,
    currency: String,
    square_measure: String,
    location: String,
    heat_period_start: String,
    heat_period_end: String,
    cool_period_start: String,
    cool_period_end: String,
    cat_title: String,
    room_title: String,
    miniserver_type: u8,
    current_user: LoxoneUser,
    device_monitor: LoxoneUUID,
    language_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneUser {
    uuid: LoxoneUUID,
    name: String,
    is_admin: bool,
    change_password: bool,
    user_rights: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneRoom {
    uuid: LoxoneUUID,
    name: String,
    image: String,
    default_rating: u8,
    is_favorite: bool,
    r#type: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoxoneTime {
    id: u16,
    name: String,
    analog: bool,
}