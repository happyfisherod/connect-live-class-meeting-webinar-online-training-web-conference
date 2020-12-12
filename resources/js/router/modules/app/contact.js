export default [{
    path: 'contacts',
    name: 'appContact',
    redirect: { name: 'appContactList' },
    meta: {
        title: 'contact.contacts',
        icon: 'fas fa-address-book',
        hideChildren: true,
        permissions: ['access-contact'],
    },
    component: {
        template: '<router-view></router-view>'
    },
    children: [{
            path: '',
            name: 'appContactList',
            meta: {
                trans: 'global.list',
                title: 'contact.contacts',
                permissions: ['access-contact']
            },
            component: () => import('@views/app/contact/index' /* webpackChunkName: "js/app/contact/index" */ ),
        },
        {
            path: 'add',
            name: 'appContactAdd',
            meta: {
                trans: 'global.add',
                title: 'contact.contact',
                permissions: ['access-contact']
            },
            component: () => import('@views/app/contact/add' /* webpackChunkName: "js/app/contact/add" */ ),
        },
        {
            path: 'import',
            name: 'appContactImport',
            meta: { 
                trans: 'global.import',
                title: 'contact.contact',
                permissions: ['access-contact']
            },
            component: () => import('@views/app/contact/import' /* webpackChunkName: "js/app/contact/import" */),
        },
        {
            path: ':uuid/edit',
            name: 'appContactEdit',
            meta: {
                trans: 'global.edit',
                title: 'contact.contact',
                permissions: ['access-contact']
            },
            component: () => import('@views/app/contact/edit' /* webpackChunkName: "js/app/contact/edit" */ ),
        },
    ]
}, ]
