import { Settings } from './types';

export const defaultSettings: Settings = {
    Schedule: [
        { fromTime: '07:00', toTime: '23:00', clockType: 'wordclock', clockSettings: { backgroundColor: '#242424', foreGroundColor: '#FFF', shadeColor: '#292929', topDistance: '1vmin', sizeFactor: 90 } }
    ],
    ForceReload: false,
    RefreshRate: 60,
    DefaultClock: 'digital',
    WordClockDefaultSettings: { backgroundColor: '#242424', foreGroundColor: '#FFFFFF', shadeColor: '#292929', topDistance: '1vmin', sizeFactor: 90 },
    DigitalClockDefaultSettings: { backgroundColor: '#000000', foreGroundColor: '#E61919', shadeColor: '#282828', topDistance: '25vmin', sizeFactor: 90 },
    TimerSettings: { backgroundColor: '#242424', foreGroundColor: '#FFFFFF', shadeColor: '#292929', topDistance: '1vmin', sizeFactor: 90 },
    Timer: 0,
    FlipClockDefaultSettings: { backgroundColor: '#242424', foreGroundColor: '#FFFFFF', shadeColor: '#292929', topDistance: '1vmin', sizeFactor: 90 },
    ClockClock24DefaultSettings: { backgroundColor: '#242424', foreGroundColor: '#964545', shadeColor: '#FFFFFF', topDistance: '30vmin', sizeFactor: 10 }
};