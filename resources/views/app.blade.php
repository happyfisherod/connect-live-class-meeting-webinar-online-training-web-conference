<!DOCTYPE html>
<html lang="hi" @if((!cache('direction') && config('config.direction') == 'rtl') || cache('direction') == 'rtl') dir="rtl" @endif>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <!-- Tell the browser to be responsive to screen width -->
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="">
        <meta name="author" content="ScriptMint">
        <title>{{env('APP_NAME')}}</title>
        <link rel="apple-touch-icon" sizes="180x180" href="{{config('config.assets.icon')}}">
        <link rel="icon" type="image/png" sizes="32x32" href="{{config('config.assets.icon')}}">
        <link rel="icon" type="image/png" sizes="16x16" href="{{config('config.assets.icon')}}">
        <link rel="manifest" href="/images/site.webmanifest">
        <link rel="mask-icon" href="/images/safari-pinned-tab.svg" color="#5e35b1">
        <link rel="shortcut icon" href="{{config('config.assets.favicon')}}">
        <meta name="apple-mobile-web-app-title" content="Connect Mint">
        <meta name="application-name" content="Connect Mint">
        <meta name="msapplication-TileColor" content="#603cba">
        <meta name="msapplication-config" content="/images/browserconfig.xml">
        <meta name="theme-color" content="#452784">
        <link href="{{ mix('/css/style.css') }}" rel="stylesheet">
        <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
        <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
        <!--[if lt IE 9]>
            <script src="/js/html5shiv.js"></script>
            <script src="/js/respond.min.js"></script>
        <![endif]-->
    </head>
    <body>
        <div id="root">
            <router-view></router-view>
        </div>
        <script src="/js/lang"></script>
        <script src="{{ mix('js/app.js') }}"></script>
    </body>
</html>
