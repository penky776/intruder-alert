use notify_rust::Notification;

fn main() {
    intruder_alert()
}

fn intruder_alert() {
    Notification::new()
        .summary("Intruder alert!")
        .body("Please confirm the detected ip address")
        .show()
        .unwrap();
}
