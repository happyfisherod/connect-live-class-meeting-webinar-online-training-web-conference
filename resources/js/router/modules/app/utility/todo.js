export default [
    {
        path: 'todos',
        name: 'appUtilityTodo',
        redirect: { name: 'appUtilityTodoList' },
        meta: { 
            title: 'utility.todo.todos', 
            icon: 'far fa-check-square',
            hideChildren: true,
            permissions: ['access-todo']
        },
        component: {
            template: '<router-view></router-view>'
        },
        children: [
            {
                path: '',
                name: 'appUtilityTodoList',
                meta: { 
                    trans: 'global.list',
                    title: 'utility.todo.todos',
                },
                component: () => import('@views/app/utility/todo/index' /* webpackChunkName: "js/app/utility/todo/index" */),
            },
            {
                path: 'add',
                name: 'appUtilityTodoAdd',
                meta: { 
                    trans: 'global.add',
                    title: 'utility.todo.todo',
                },
                component: () => import('@views/app/utility/todo/add' /* webpackChunkName: "js/app/utility/todo/add" */),
            },
            {
                path: ':uuid/edit',
                name: 'appUtilityTodoEdit',
                meta: { 
                    trans: 'global.edit',
                    title: 'utility.todo.todo',
                },
                component: () => import('@views/app/utility/todo/edit' /* webpackChunkName: "js/app/utility/todo/edit" */),
            },
            {
                path: ':uuid',
                name: 'appUtilityTodoView',
                meta: { 
                    trans: 'global.view',
                    title: 'utility.todo.todo',
                },
                component: () => import('@views/app/utility/todo/view' /* webpackChunkName: "js/app/utility/todo/view" */),
            }
        ]
    },
]