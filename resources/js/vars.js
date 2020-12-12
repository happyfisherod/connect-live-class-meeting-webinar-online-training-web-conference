const colors = {
    'white': '#ffffff',
    'whitish': '#fafbfd',
    'blackish': '#131517',
    'black': '#000000',
    'gray100': '#f8f9fd',
    'gray200': '#e9ecf1',
    'gray300': '#dee2e9',
    'gray400': '#ced4dd',
    'gray500': '#adb5c0',
    'gray600': '#6c7580',
    'gray700': '#495060',
    'gray800': '#343a43',
    'gray900': '#212532',
    'blue': '#5e72e4',
    'indigo': '#581b98',
    'purple': '#7a22a5',
    'pink': '#f3a4b5',
    'red': '#f5365c',
    'redish': '#e00c51',
    'orange': '#fb6340',
    'yellow': '#ffd600',
    'green': '#2dce89',
    'teal': '#2bffc6',
    'cyan': '#11cdef',
    'primary': '#581b98',
    'dark-primary': '#320f57',
    'light-primary': '#7e27d9',
    'secondary': '#e00c51',
    'dark-secondary': '#970837',
    'success': '#2dce89',
    'info': '#11cdef',
    'warning': '#fb6340',
    'danger': '#f5365c',
    'default': '#0a346d',
    'gray-lightest': '#f8f9fd',
    'gray-lighter': '#e9ecf1',
    'gray-light': '#dee2e9',
    'light': '#dee2e9',
    'gray-chalk': '#ced4dd',
    'gray': '#adb5c0',
    'dark': '#6c7580',
    'gray-dark': '#6c7580',
    'gray-darker': '#495060',
    'gray-charcoal': '#343a43',
    'gray-darkest': '#212532'
}

const momentToDatepicker = {
    "D-MM-YY": "j-m-y",
    "D-MM-YYYY": "j-m-Y",
    "DD-MM-YYYY": "d-m-Y",
    "MM-DD-YYYY": "m-d-Y",
    "YYYY-MM-DD": "Y-m-d",
    "MMM D, YYYY": "M j, Y",
    "MMMM D, YYYY": "F j, Y",
    "dddd, MMM D, YYYY": "l, M j, Y",
    "dddd, MMMM D, YYYY": "l, F j, Y",
    "D MMM YYYY": "j M Y",
    "D MMMM YYYY": "j F Y",
    "dddd, D MMM YYYY": "l, j M Y",
    "dddd, D MMMM YYYY": "l, j F Y",
}

const momentToTimepicker = {
    "H:m": "H:i",
    "H:m a": "H:i K",
    "H:m A": "H:i K",
    "H:mm": "H:i K",
    "H:mm a": "H:i K",
    "H:mm A": "H:i K",
    "HH:mm": "H:i K",
    "HH:mm a": "H:i K",
    "HH:mm A": "H:i K",
    "h:m": "h:i K",
    "h:m a": "h:i K",
    "h:m A": "h:i K",
    "h:mm": "h:i K",
    "h:mm a": "h:i K",
    "h:mm A": "h:i K",
    "hh:mm": "h:i K",
    "hh:mm a": "h:i K",
    "hh:mm A": "h:i K",
    "H:m:ss": "H:i:S",
    "H:m:ss a": "H:i:S K",
    "H:m:ss A": "H:i:S K",
    "H:mm:ss": "H:i:S K",
    "H:mm:ss a": "H:i:S K",
    "H:mm:ss A": "H:i:S K",
    "HH:mm:ss": "H:i:S",
    "HH:mm:ss a": "H:i:S K",
    "HH:mm:ss A": "H:i:S K",
    "h:m:ss": "h:i:S K",
    "h:m:ss a": "h:i:S K",
    "h:m:ss A": "h:i:S K",
    "h:mm:ss": "h:i:S K",
    "h:mm:ss a": "h:i:S K",
    "h:mm:ss A": "h:i:S K",
    "hh:mm:ss": "h:i:S K",
    "hh:mm:ss a": "h:i:S K",
    "hh:mm:ss A": "h:i:S K",
}

const momentToMonthpicker = {
    "MMM YYYY": "M Y",
    "MMMM YYYY": "F Y",
}

const datepickerConfig = {
    wrap: true,
    allowInput: false,
    dateFormat: "Y-m-d",
    altInput: true,
    altFormat: "F j, Y",
    locale: {
        firstDayOfWeek: 1
    },
}

const datepickerRangeConfig = {
    ...datepickerConfig,
    mode: 'range',
}

const datepickerMultipleConfig = {
    ...datepickerConfig,
    mode: 'multiple',
}

const timepickerConfig = {
    enableTime: true,
    noCalendar: true,
    altFormat: "h:i K",
    dateFormat: "H:i:S",
    time_24hr: false,
    wrap: true,
    allowInput: false,
    altInput: true,
}

const datetimepickerConfig = {
    enableTime: true,
    wrap: true,
    allowInput: false,
    altFormat: "F j, Y h:i K",
    dateFormat: "Y-m-d H:i:S",
    time_24hr: false,
    altInput: true,
    locale: {
        firstDayOfWeek: 1
    },
}

const onMonthOrYearChange = function(dObj, dStr, fp) {
    fp.setDate(new Date(fp.currentYear, fp.currentMonth), true)
}

const monthpickerConfig = {
    wrap: true,
    allowInput: false,
    dateFormat: "Y-m",
    altInput: true,
    altFormat: "F Y",
    locale: {
        firstDayOfWeek: 1
    },
}

const daymonthpickerConfig = {
    wrap: true,
    allowInput: false,
    dateFormat: "m-d",
    altInput: true,
    altFormat: "F j",
    locale: {
        firstDayOfWeek: 1
    },
}

const currencyIcons = {
    'INR': 'rupee-sign',
    'USD': 'dollar-sign',
}

const colorsForStatus = {
    'activated': 'success',
    'PENDING_APPROVAL': 'info',
    'disapproved': 'warning',
    'pending_activation': 'primary',
    'banned': 'dark',

    'pending': 'primary',
    'approved': 'success',
    'allotted': 'success',
    'rejected': 'danger',
    'cancelled': 'danger',

    'unpaid': 'danger',
    'paid': 'success',
    'partially_paid': 'warning',
    'not_applicable': 'dark',
    
    'open': 'info',
    'closed': 'success',
    'partially_closed': 'primary',
    'missed': 'dark',

    'meeting-scheduled': 'primary',
    'meeting-cancelled': 'danger',
    'meeting-live': 'success',
}

const defaultCurrency = {
    "description": "United States Dollar",
    "name": "USD",
    "symbol": "$",
    "icon": "dollar-sign",
    "position": "prefix",
    "decimal": 2,
    "thousand": 3,
    "decimal_delimeter": ".",
    "thousand_delimeter": ","
}

const keepAddingOptions = [
    { uuid: 'clear_all', name: 'clear_all' },
    { uuid: 'clear_all_but_selected', name: 'clear_all_but_selected' },
    { uuid: 'clear_only_selected', name: 'clear_only_selected' },
]

const vars = {
    localStorageKey: process.env.MIX_APP_NAME + '_' + process.env.MIX_APP_ENV,
    localStorageVersionKey: process.env.MIX_APP_NAME + '_' + process.env.MIX_APP_ENV + '_version',
    serviceWorkerKey: process.env.MIX_APP_NAME + '_' + process.env.MIX_APP_ENV,
    appVersion: process.env.MIX_APP_VERSION,
    serviceWorkerVersion: 'v1',
    defaultDateTimeFormat: 'lll',
    defaultDateFormat: 'll',
    defaultTimeFormat: 'LT',
    serverTimeFormat: 'HH:mm:ss',
    serverDateFormat: 'YYYY-MM-DD',
    serverDateTimeFormat: 'YYYY-MM-DD HH:mm:ss',
    monthYearFormat: 'MMM YYYY',
    datepickerConfig: datepickerConfig,
    timepickerConfig: timepickerConfig,
    datepickerRangeConfig: datepickerRangeConfig,
    datepickerMultipleConfig: datepickerMultipleConfig,
    datetimepickerConfig: datetimepickerConfig,
    monthpickerConfig: monthpickerConfig,
    onMonthOrYearChange: onMonthOrYearChange,
    daymonthpickerConfig: daymonthpickerConfig,
    momentToDatepicker: momentToDatepicker,
    momentToTimepicker: momentToTimepicker,
    momentToMonthpicker: momentToMonthpicker,
    loaderColor: colors.primary,
    colors: colors,
    colorsForStatus: colorsForStatus,
    currencyIcons: currencyIcons,
    keepAddingOptions: keepAddingOptions,
    defaultCurrency: defaultCurrency,
}

export default vars
