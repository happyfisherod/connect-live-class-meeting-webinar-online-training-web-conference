<template>
    <div class="call-page" 
            :data-page-background-color="uiConfigs.pageContainerBackgroundColor" 
            :data-footer-background-color="uiConfigs.leftSidebarColor">

        <template v-if="!duplicateTab">
            <div :class="['video-list', {'has-no-video': !hasVideos}, {'agenda-comments-visible': pageConfigs.showAgenda || pageConfigs.showComments}]" ref="videoListEle">

                <template v-if="hasVideos">
                    <div v-for="(item, itemIndex) in videoList" :key="`${item.uuid}${item.id}`" :class="['video-item', {'maximized': item.maximized}, {'local': item.local}, {'screen': item.screen}, {'fullscreen-item': item.id === fullScreenItemId}, {'audio-muted': item.audioMuted}, {'video-muted': item.videoMuted || !item.hasVideo }, {'no-stream': !item.status}]" @dblclick="changeFocus(item)">
                        
                        <div class="video-wrapper">
                            <video autoplay playsinline ref="videos" :muted="item.muted" :id="item.id" :poster="item.status  ? null : '/images/video/no-stream.jpg'" :class="[{'no-poster': item.status && !item.videoMuted}]"></video>
                        </div>

                        <div class="caption">
                            <h6 v-if="item.status">
                                <span class="text-xs mr-1 text-success"><i class="fas fa-circle"></i></span>

                                <template v-if="item.local">
                                    {{ item.screen ? $t('meeting.your_screen') : $t('meeting.you') }}
                                </template>

                                <template v-else>
                                    {{ item.screen ? `${item.name}${$t('meeting.screen')}` : item.name }}
                                </template>
                            </h6>
                            <h6 v-else>
                                <span class="text-xs mr-1 text-danger"><i class="fas fa-circle"></i></span>

                                {{ item.local ? (item.localScreen ? $t('meeting.your_screen') : $t('meeting.you')) : item.name }}

                                <span class="bracketed text-danger">{{ $t('meeting.left') }}</span>
                            </h6>

                            <base-dropdown v-if="!item.maximized" tag="div" class="video-item-actions" direction="up" menu-classes="animated faster menuFadeInUpSmall" position="right" design="gray-darker">
                                <base-button slot="title" type="button" design="dark-primary" size="sm" data-toggle="dropdown" role="button"><i class="fas fa-ellipsis-v"></i></base-button>

                                <a v-if="!item.maximized" class="dropdown-item" @click="changeFocus(item)">Focus this!</a>
                            </base-dropdown>
                        </div>

                        <div v-if="!item.local" class="custom-controls-wrapper">
                            <div class="custom-controls">
                                <div class="status-icon" v-if="item.audioMuted && !item.videoMuted">
                                    <i class="fas fa-microphone-slash disabled-text"></i>
                                </div>
                                <button @click="toggleRemoteAudio(item, itemIndex)">
                                    <i :class="['fas', {'fa-volume-up enabled-text': !item.muted}, {'fa-volume-off disabled-text': item.muted}]"></i>
                                </button>
                                <button @click="toggleFullScreen(item, itemIndex)">
                                    <i :class="['fas', {'fa-expand': !fullScreenInOn}, {'fa-compress': fullScreenInOn}]"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </template>
                
            </div>


            <div class="call-footer">
                <div class="logo-wrapper">
                    <app-logo :place="pageConfigs.isDark ? 'dark':'light'" size="sm" />
                </div>

                <div class="call-actions">
                    <template v-if="entity && entity.status && videoList.length">
                        <template v-if="localVideo">

                            <template v-if="pageConfigs.showEnableVideoBtn">
                                <button v-if="pageConfigs.enableVideo" type="button" class="btn action enabled-text" @click="toggleVideo" v-b-tooltip.hover.d500 :title="$t('meeting.mute_video')"><i class="fas fa-video"></i></button>

                                <button v-else type="button" class="btn action disabled-text" @click="toggleVideo" v-b-tooltip.hover.d500 :title="$t('meeting.unmute_video')"><i class="fas fa-video-slash"></i></button>
                            </template>

                            <template v-if="pageConfigs.showEnableAudioBtn">
                                <button v-if="pageConfigs.enableAudio" type="button" class="btn action enabled-text" @click="toggleAudio" v-b-tooltip.hover.d500 :title="$t('meeting.mute_audio')"><i class="fas fa-microphone"></i></button>

                                <button v-else type="button" class="btn action disabled-text" @click="toggleAudio" v-b-tooltip.hover.d500 :title="$t('meeting.unmute_audio')"><i class="fas fa-microphone-slash"></i></button>
                            </template>

                        </template>


                        <template v-if="pageConfigs.showShareScreenBtn">
                            <button v-if="localScreenStreamid" type="button" class="btn action" @click="stopSharingScreen" v-b-tooltip.hover.d500 :title="$t('meeting.stop_sharing_screen')"><i class="fas fa-minus-square"></i></button>

                            <button v-else type="button" class="btn action" @click="shareScreen" v-b-tooltip.hover.d500 :title="$t('meeting.share_screen')"><i class="fas fa-desktop"></i></button>
                        </template>

                        <div class="separator"></div>

                        <button v-if="entity.canModerate" type="button" class="btn action" @click="endMeeting" v-b-tooltip.hover.d500 :title="$t('meeting.end_meeting')"><i class="fas fa-calendar-times"></i></button>

                        <button type="button" class="btn action" @click="getOffline" v-b-tooltip.hover.d500 :title="$t('meeting.leave_meeting')"><i class="fas fa-sign-out-alt"></i></button>
                    </template>

                    <button v-if="entity && entity.config && entity.config.enableComments" type="button" :class="['btn action', {'pulse': newComments}]" @click="toggleComments" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showComments ? 'global.hide' : 'global.show'), { attribute: $t('comment.comments')})"><i :class="[{'fas fa-comment-slash': pageConfigs.showComments}, {'far fa-comment': !pageConfigs.showComments}]"></i></button>

                    <button type="button" class="btn action" @click="toggleAgenda" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showAgenda ? 'global.hide' : 'global.show'), { attribute: $t('general.agenda')})"><i class="fas fa-quote-left"></i></button>

                    <div class="separator"></div>

                    <button type="button" class="btn action" @click="toggleDark" v-b-tooltip.hover.d500 :title="$t('global.switch', { attribute: pageConfigs.isDark ? $t('config.ui.light') : $t('config.ui.dark')})"><i class="fas fa-adjust"></i></button>
                </div>
            </div>
        </template>

        <div v-else class="duplicate-tab d-flex justify-content-center align-items-center min-height-90vh">
            <h2>{{ $t('meeting.duplicate_tab') }}</h2>
        </div>
    </div>
</template>

<script>
    import call from '@mixins/call'

    export default {
        extends: call,
        components: {},
    }

</script>

<style lang="scss">
    @import '~@js/core/assets/scss/imports.scss';
    @import "~@js/core/assets/scss/partials/palettes";

    .call-page {
        width: 100vw;
        height: 100vh;
        max-height: 100vh;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        align-items: stretch;

        .video-list {
            display: flex;
            flex-grow: 1;
            justify-content: space-around;
            align-items: center;
            flex-wrap: wrap;
            padding-bottom: 3rem;

        }





        .call-footer {
            width: 100%;
            display: flex;
            justify-content: space-around;
            height: $navbar-height;
            align-items: stretch;

            .logo-wrapper {
                display: flex;
                align-items: center;
                padding-left: $margin-common;
            }

            .call-actions {
                text-align: right;
                display: none;

                &>.separator {
                    width: 2px;
                    border-left: 2px solid rgba(0,0,0,0.1);
                    background: rgba(0,0,0,0.05);
                }

                &>.btn {
                    box-shadow: none;
                    font-size: 1rem;
                    margin-right: 0;

                    &:hover {
                        box-shadow: none;
                        background: rgba(0, 0, 0, 0.3);
                    }

                    &:active {
                        background: rgba(0, 0, 0, 0.6);
                        box-shadow: inset 0 0 10px 0px rgba(0, 0, 0, 0.1);
                    }

                    &.disabled-text {
                        color: $danger;

                    &:hover {
                        color: $danger;
                    }
                }

                &.enabled-text {
                    color: $success;

                    &:hover {
                        color: $success;
                    }
                }
            }
        }
        }
    }

    @each $key,
    $value in $default-palette {
        [data-page-background-color="#{$key}"] {
            background-color: map-get($value, "background-color");
            color: map-get($value, "foreground-color");
        }

        [data-footer-background-color="#{$key}"] {
            .call-footer {
                background-color: map-get($value, "background-color");
                color: map-get($value, "foreground-color");
            }
        }
    }

</style>
