export default [{
    path: 'calls',
    name: 'appCall',
    redirect: { name: 'appCallList' },
    meta: {
        title: 'call.calls',
        icon: 'fas fa-phone-alt',
        hideChildren: true,
        isNotNav: true,
        permissions: ['list-meeting'],
    },
    component: {
        template: '<router-view></router-view>'
    },
    children: [{
            path: '',
            name: 'appCallList',
            meta: {
                trans: 'global.list',
                title: 'call.calls',
                permissions: ['list-meeting']
            },
            component: () => import('@views/app/call/index' /* webpackChunkName: "js/app/call/index" */ ),
        },
    ]
}, ]
