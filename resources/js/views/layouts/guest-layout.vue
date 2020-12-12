<template>
    <div class="guest-layout">
        <transition appear name="fade-transform" mode="out-in">
            <router-view></router-view>
        </transition>
        <!-- <notifications group="guest" /> -->
    </div>
</template>

<script>
    export default {}
</script>

<style lang="scss">
    .guest-layout {
        width: 100%;
        min-height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        background-position: center bottom;
        background: #3f0073;
        background: radial-gradient(ellipse at bottom, #581b97 0%, #030617 80%);
        filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#ff005d', endColorstr='#3f0073', GradientType=1);
        position: relative;

        &:before {
            content: "";
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;

            background: linear-gradient(135deg, #ff005d 12px, #3f0073 22px, #3f0073 22px, transparent 22px, transparent 62px, #3f0073 64px, #3f0073 69px, transparent 69px), linear-gradient(225deg, #ff005d 22px, #3f0073 22px, #3f0073 24px, transparent 24px, transparent 67px, #3f0073 67px, #3f0073 69px, transparent 69px) 0 65px;
            background-color: #ff005d;
            background-size: 64px 128px;
            opacity: 0.05;
        }


        &>>>.guest-page {
            display: flex;
            flex: 1 1 auto;
            flex-direction: column;
            min-height: 100vh;
            width: 100%;
            justify-content: center;
        }
    }

</style>
