interface User {
    user_id: number,
    username: string,
    Username: string,
    iat: number,
    exp: number
}

interface DbUser {
    Id: number,
    username: string,
    Username: string,
    Password: string,
    Token: string
    Salt: string,
    iat: number,
    exp: number,
    Settings: Settings
}

interface DbError {
    message: string
}

interface ScheduleEntry {
    fromTime: string,
    toTime: string,
    clockType: string,
    clockSettings: ClockSettings
}

interface Settings {
    Schedule: ScheduleEntry[],
    ForceReload: boolean,
    RefreshRate: number,
    DefaultClock: string,
    WordClockDefaultSettings: ClockSettings,
    DigitalClockDefaultSettings: ClockSettings,
    TimerSettings: ClockSettings,
    FlipClockDefaultSettings: ClockSettings,
    ClockClock24DefaultSettings: ClockSettings,
    Timer: number
}

interface ClockSettings {
    backgroundColor: string,
    foreGroundColor: string,
    shadeColor: string,
    topDistance: Property.PaddingTop<TLength>,
    sizeFactor: number,
    showSeconds?: boolean
}

interface ClockComponentProps {
    time: Date,
    clockSettings: ClockSettings,
    timer?: number,
    finished?: () => void
}

export {
    User,
    DbUser,
    DbError,
    Settings,
    ClockComponentProps,
    ClockSettings
};