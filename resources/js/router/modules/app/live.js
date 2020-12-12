export default [{
    path: 'live/meetings/:uuid',
    name: 'liveMeeting',
    meta: {
        title: 'meeting.meeting_details',
    },
    component: () => import('@views/app/meeting/live' /* webpackChunkName: "js/app/meeting/live" */ ),
}, {
    path: 'live/calls/:uuid',
    name: 'liveCall',
    meta: {
        title: 'call.on_call',
    },
    component: () => import('@views/app/call/live' /* webpackChunkName: "js/app/call/live" */ ),
}, ]
