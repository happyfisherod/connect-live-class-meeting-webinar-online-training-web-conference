import { getOptionRoutes } from './config/module-config'

export default [{
    path: 'meetings',
    name: 'appMeeting',
    redirect: { name: 'appMeetingList' },
    meta: {
        title: 'meeting.meetings',
        icon: 'far fa-calendar-alt',
        hideChildren: true,
        permissions: ['list-meeting', 'create-meeting', 'edit-meeting'],
    },
    component: {
        template: '<router-view></router-view>'
    },
    children: [{
            path: '',
            name: 'appMeetingList',
            meta: {
                trans: 'global.list',
                title: 'meeting.meetings',
                permissions: ['list-meeting']
            },
            component: () => import('@views/app/meeting/index' /* webpackChunkName: "js/app/meeting/index" */ ),
        }, 
        {
            path: 'config',
            name: 'appMeetingConfig',
            redirect: { name: 'appMeetingConfigGeneral' },
            meta: {
                title: 'config.config',
                permissions: ['access-meeting-config'],
                isConfigRoute: true,
            },
            component: () => import('@views/app/meeting/config/index' /* webpackChunkName: "js/app/meeting/config/index" */ ),
            children: [{
                    path: '',
                    name: 'appMeetingConfigGeneral',
                    meta: {
                        title: 'config.general',
                    },
                    component: () => import('@views/app/meeting/config/general' /* webpackChunkName: "js/app/meeting/config/general" */ ),
                },
                getOptionRoutes({
                    path: 'categories',
                    entityTitle: 'meeting.meeting_category.category',
                    entitiesTitle: 'meeting.meeting_category.categories',
                    entityDescription: 'meeting.meeting_category.module_description',
                    routeNamePrefix: 'appMeetingConfigCategory',
                    permissionRequired: 'access-meeting-config',
                    optionType: 'meeting_category',
                    hasSlug: false,
                }),
            ]
        },
        {
            path: 'add',
            name: 'appMeetingAdd',
            meta: {
                trans: 'global.add',
                title: 'meeting.meeting',
                permissions: ['create-meeting']
            },
            component: () => import('@views/app/meeting/add' /* webpackChunkName: "js/app/meeting/add" */ ),
        },
        {
            path: ':uuid/edit',
            name: 'appMeetingEdit',
            meta: {
                trans: 'global.edit',
                title: 'meeting.meeting',
                permissions: ['edit-meeting']
            },
            component: () => import('@views/app/meeting/edit' /* webpackChunkName: "js/app/meeting/edit" */ ),
        },
        {
            path: ':uuid/duplicate',
            name: 'appMeetingDuplicate',
            meta: { 
                trans: 'global.add',
                title: 'meeting.meeting',
            },
            component: () => import('@views/app/meeting/edit' /* webpackChunkName: "js/app/meeting/edit" */),
        },
        {
            path: ':subUuid/invitees/add',
            name: 'appMeetingInviteeAdd',
            meta: { 
                trans: 'global.add',
                title: 'meeting.invitee.invitees',
            },
            component: () => import('@views/app/meeting/invite' /* webpackChunkName: "js/app/meeting/invite" */),
        },
        {
            path: ':subUuid/config',
            name: 'appMeetingSingleConfig',
            meta: { 
                trans: 'global.config',
                title: 'meeting.meeting',
            },
            component: () => import('@views/app/meeting/config' /* webpackChunkName: "js/app/meeting/config" */),
        },
        {
            path: ':uuid',
            name: 'appMeetingView',
            meta: {
                trans: 'global.view',
                title: 'meeting.meeting',
                permissions: ['list-meeting']
            },
            component: () => import('@views/app/meeting/view' /* webpackChunkName: "js/app/meeting/view" */ ),
        },
    ]
}, ]
