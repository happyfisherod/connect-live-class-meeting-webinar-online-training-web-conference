import system from './system';

// loading app routes
import meeting from './meeting'
import call from './call'
import contact from './contact'
import segment from './segment'
import user from './user'

import utility from './utility'
import config from './config'
import uiConfig from './ui-config'
import activity from './activity'

export default [
    {
        path: 'dashboard',
        name: 'appDashboard',
        meta: {
            title: 'dashboard.dashboard', 
            description: '', 
            icon: 'fas fa-home',
        },
        components: {
            header:  () => import('@views/app/dashboard/header' /* webpackChunkName: "js/app/dashboard/header" */),
            default:  () => import('@views/app/dashboard/index' /* webpackChunkName: "js/app/dashboard/index" */),
        },
    },
    {
        path: '',
        meta: { 
            isHiddenNav: true,
        },
        components: {
            header:  () => import('@views/layouts/partials/app-common-page-header' /* webpackChunkName: "js/layouts/partials/app-common-page-header" */),
            default: { template: '<router-view></router-view>' },
        },
        children: [
            ...system,
            
            ...meeting,
            ...call,
            ...segment,
            ...contact,
            ...user,
            
            ...utility,
            ...config,
            ...uiConfig,
            ...activity,
        ]
    },
]