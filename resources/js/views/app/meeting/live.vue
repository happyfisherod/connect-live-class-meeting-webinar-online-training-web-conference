<template>
    <base-container with-loader :is-loading="isLoading" :loader-color="vars.loaderColor" :overlay-color="uiConfigs.pageColorSchemeType" loader-size="screen" :class="['meeting-page']" :data-page-background-color="uiConfigs.pageBackgroundColor" :data-card-background-color="uiConfigs.pageContainerBackgroundColor">

        <div v-if="!duplicateTab" :class="['meeting-footer', {'has-videos': hasVideos}]" :data-footer-background-color="uiConfigs.leftSidebarColor">

            <div class="logo-wrapper">
                <app-logo place="sidebar" size="sm" />
            </div>

            <div class="meeting-actions">
                <button type="button" class="btn action" @click="$router.push({ name: 'appMeetingList'})" v-b-tooltip.hover.d500 :title="$t('general.back')"><i class="fas fa-chevron-left"></i></button>

                <div class="separator"></div>

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

                <button v-if="entity && entity.config && entity.config.enableComments" type="button" :class="['btn action comments-toggle-btn', {'pulse': newComments}]" @click="toggleComments" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showComments ? 'global.hide' : 'global.show'), { attribute: $t('comment.comments')})"><i :class="[pageConfigs.showComments ? 'fas fa-comment-slash' : 'far fa-comment']"></i></button>

                <button type="button" class="btn action agenda-toggle-btn" @click="toggleAgenda" v-b-tooltip.hover.d500 :title="$t((pageConfigs.showAgenda ? 'global.hide' : 'global.show'), { attribute: $t('general.agenda')})"><i class="fas fa-quote-left"></i></button>
            </div>
        </div>


        <div v-if="!duplicateTab" :class="['video-list', hasVideosClasses, {'agenda-comments-visible': pageConfigs.showAgenda || pageConfigs.showComments}]" ref="videoListEle">


            <card shadow v-if="pageConfigs.showAgenda || pageConfigs.showComments" class="video-item agenda-comments" :body-classes="[{'agenda-wrapper': pageConfigs.showAgenda}]">

                <div class="meeting-agenda-container">
                    <vue-scroll ref="vue-scroll-agenda" id="vue-scroll-agenda">
                        <template v-if="entity">
                            <h4 class="meeting-title" v-once>{{ entity.title }}</h4>

                            <div class="text-muted mt-3">
                                <span v-once>{{ $t('meeting.props.type') }}: {{ entity.type.name }},</span>
                                <span v-once>{{ $t('meeting.meeting_category.category') }}: {{ entity.category.name }}</span>
                            </div>

                            <view-paragraph class="mt-3" :label="$t('meeting.props.agenda')" :value="entity.agenda" />

                            <view-paragraph v-if="entity.description" class="mt-3" :label="$t('meeting.props.description')" :value="entity.description" html />

                            <view-uploads v-if="entity.attachments" :class="['mt-3', uiConfigs.colorSchemeType]" :label="$t('upload.attachments')" :name-label="$t('upload.attachment')" :value="entity.attachments" download-button-classes="text-gray" :url-prefix="`/meetings/${uuid}/downloads`" />
                        </template>
                    </vue-scroll>
                </div>

                <!-- <comments class="comments-wrapper" v-else-if="entity.config && entity.config.enableComments && pageConfigs.showComments" :is-dark="pageConfigs.isDark" :is-loading="isLoading" :user="user" :meeting="entity" :members="membersLive" :channel="this.channel" /> -->
            </card>


            <template v-if="hasVideos">
                <card shadow v-for="(item, itemIndex) in videoList" :key="`${item.uuid}${item.id}`" :class="['video-item', {'maximized': item.maximized}, {'local': item.local}, {'screen': item.screen}, {'fullscreen-item': item.id === fullScreenItemId}, {'audio-muted': item.audioMuted}, {'video-muted': item.videoMuted || !item.hasVideo }, {'no-stream': !item.status}]" @dblclick="changeFocus(item)">

                    <div class="video-wrapper">
                        <video autoplay playsinline ref="videos" :muted="item.muted" :id="item.id" :poster="item.status  ? null : '/images/video/no-stream.jpg'" :class="[{'no-poster': item.status && !item.videoMuted}]"></video>
                    </div>

                    <div class="caption">
                        <h6>
                            <span :class="['text-xs mr-1', {'text-success': item.status}, {'text-danger': !item.status}]"><i class="fas fa-circle"></i></span>

                            <template v-if="item.local">
                                {{ item.screen ? $t('meeting.your_screen') : $t('meeting.you') }}
                            </template>

                            <template v-else>
                                {{ item.screen ? `${item.name}${$t('meeting.screen')}` : item.name }}
                            </template>

                            <span v-if="!item.status" class="bracketed text-danger">{{ $t('meeting.left') }}</span>
                        </h6>
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
                </card>
            </template>


            <card v-else shadow class="video-item wait-box maximized">
                <template v-if="entity">

                    <template v-if="entity.status === 'scheduled'">

                        <flip-countdown class="my-3" v-if="startDateTimeIsFuture" :deadline="entity.startDateTime" />

                        <template v-else>
                            <template v-if="entity.canModerate">
                                <h5 class="text-muted text-center my-3">
                                    {{ $t('meeting.waiting_for_you_to_start') }}
                                </h5>

                                <div class="d-flex justify-content-center my-3">
                                    <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                                </div>
                            </template>

                            <h5 v-else class="text-muted text-center my-3">
                                {{ $t('meeting.starting_any_time_now') }}
                            </h5>
                        </template>

                        <div class="text-center my-3">
                            <span class="text-muted">{{ $t('meeting.scheduled_for') }}</span><span class="text-muted-lg m-l-5" v-b-tooltip.hover.d500 :title="[entity.startDateTime, vars.serverDateTimeFormat] | moment(vars.defaultDateTimeFormat)">{{ [entity.startDateTime, vars.serverDateTimeFormat] | moment('calendar', null, { sameElse: vars.defaultDateTimeFormat }) }}</span>
                        </div>

                        <div v-if="liveMembersCount > 0" class="text-muted text-center my-3">
                            <span class="text-xs text-success mr-1"><i class="fas fa-circle"></i></span>
                            <animated-number :number="liveMembersCount" :delay="100" />
                            <span v-if="liveMembersCount>1">{{ $t('meeting.members_online') }}</span>
                            <span v-else>{{ $t('meeting.member_online') }}</span>
                        </div>

                        <template v-if="entity.canModerate">
                            <div class="d-flex justify-content-center my-3">
                                <base-button type="button" design="gray-darker" size="sm" @click="cancelMeeting">
                                    <i class="fas fa-times m-r-5"></i> {{ $t('meeting.cancel') }}</base-button>

                                <base-dropdown tag="div" size="sm">
                                    <base-button slot="title" type="button" design="gray-darker" size="sm" data-toggle="dropdown" role="button">
                                        <i class="far fa-clock m-r-5"></i>
                                        <span class="nav-link-inner--text">{{ $t('meeting.snooze') }}</span>
                                        <i class="fas fa-chevron-down m-l-5"></i>
                                    </base-button>

                                    <template>
                                        <button type="button" class="dropdown-item" v-for="opt in snoozeOpts" @click="snooze(opt.uuid)">{{ opt.name }} {{ $t(`list.general.durations.${opt.type}`) }}</button>
                                    </template>
                                </base-dropdown>
                            </div>
                        </template>

                    </template>


                    <template v-else-if="entity.status === 'live'">
                        <template v-if="roomIdAlive">
                            <h5 class="text-muted text-center my-3">
                                {{ $t('meeting.is_live_now') }}
                            </h5>

                            <div class="d-flex justify-content-center my-3">
                                <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                            </div>
                        </template>

                        <template v-else>
                            <template v-if="entity.canModerate">
                                <h5 class="text-muted text-center my-3">
                                    {{ $t('meeting.waiting_for_you_to_start') }}
                                </h5>

                                <div class="d-flex justify-content-center my-3">
                                    <base-button type="button" design="primary" size="lg" @click="getOnline">{{ $t('global.click_to', { attribute: $t('meeting.get_live') }) }}</base-button>
                                </div>
                            </template>

                            <h5 v-else class="text-muted text-center my-3">
                                {{ $t('meeting.starting_any_time_now') }}
                            </h5>
                        </template>

                        <div v-if="liveMembersCount > 0" class="text-muted text-center my-3">
                            <span class="text-xs text-success mr-1"><i class="fas fa-circle"></i></span>
                            <animated-number :number="liveMembersCount" :delay="100" />
                            <span v-if="liveMembersCount>1">{{ $t('meeting.members_online') }}</span>
                            <span v-else>{{ $t('meeting.member_online') }}</span>
                        </div>
                    </template>


                    <template v-else-if="entity.status === 'cancelled'">
                        <h4 class="text-muted text-center my-3">
                            {{ $t('meeting.meeting_cancelled') }}
                        </h4>
                    </template>

                    <template v-else-if="entity.status === 'ended'">
                        <h4 class="text-muted text-center my-3">
                            {{ $t('meeting.meeting_ended') }}
                        </h4>
                    </template>

                </template>
            </card>


        </div>

        <card v-else shadow class="duplicate-tab d-flex justify-content-center align-items-center min-height-90vh">
            <h2>{{ $t('meeting.duplicate_tab') }}</h2>
        </card>
    </base-container>
</template>

<script>
    import meeting from '@mixins/meeting'

    import FlipCountdown from 'vue2-flip-countdown'
    import Comments from './partials/comments'

    export default {
        extends: meeting,
        components: {
            FlipCountdown,
            Comments,
        },
    }

</script>