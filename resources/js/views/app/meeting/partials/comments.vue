<template>
    <div class="comments">

        <div :class="['comments-list', {'no-comments': !hasComments}]">
            <template v-if="hasComments">
                <div class="comments-list-container">
                    <vue-scroll ref="vue-scroll-comments" id="vue-scroll-comments" @handle-scroll="handleScrollComplete">
                        <div class="comments-list-wrapper">

                            <div class="spacer-div my-3">
                                <br>
                            </div>

                            <div v-for="comment in feed.data" :class="['comment-item', {'own-comment': comment.user.uuid === user.uuid}]" :key="comment.uuid">
                                <div class="user-image-wrapper mr-2">
                                    <user-avatar :user="comment.user" :size="40" />
                                </div>

                                <div class="comment-details-wrapper">
                                    <div class="comment-header">
                                        <h6 class="comment-user">{{ comment.user.name }}</h6>
                                        <span class="comment-created-at small">{{ [comment.createdAt, vars.serverDateTimeFormat] | moment('from')}}</span>
                                    </div>

                                    <div class="comment-body" v-html="comment.body"></div>

                                    <div v-if="comment.attachments" class="comment-attachments comma-list">
                                        <a v-for="attachment in comment.attachments" :href="`/meetings/${uuid}/downloads/${attachment.uuid}`" target="_blank"><i class="fas fa-paperclip"></i> <span>{{ attachment.name }}</span></a>
                                    </div>
                                </div>
                            </div>

                            <div v-if="isFetching" class="d-flex justify-content-center my-4">
                                <animated-loader :is-loading="isFetching" :loader-color="vars.colors.light" overlay-color="transparent" size="inline" loader-size="30px" />
                            </div>

                            <div v-if="noMoreComments" class="comment-item my-4 d-flex justify-content-center align-items-center">
                                <h5 class="text-muted">
                                    {{ $t('comment.no_more_comments') }}
                                </h5>
                            </div>
                        </div>
                    </vue-scroll>
                </div>
            </template>

            <div v-else class="d-flex justify-content-center align-items-center min-height-300px">
                <h4 class="text-muted">
                    {{ $t('comment.no_comments_yet') }}
                </h4>
            </div>
        </div>

        <div class="typing-indicator small min-height-20px">
            <span v-show="typingUser">@{{ typingUser }} {{ $t('general.is_typing') }}</span><span> </span>
        </div>

        <div class="new-comment mt-2">
            <animated-loader :is-loading="isPosting" :loader-color="vars.loaderColor" overlay-color="dark" />

            <div class="comment-field-wrapper">
                <at :members="members" name-key="username" v-model="newComment.body">
                    <template slot="item" slot-scope="s">
                        <span v-text="s.item.name">{{ s.item.name }}</span>
                        <span class="bracketed text-muted-md">{{ s.item.username }}</span>
                    </template>

                    <div class="new-comment-input form-control" contenteditable :data-placeholder="$t('comment.type_a_comment')" ref="newCommentInput" @keydown="isTyping" @keydown.enter="enterPressed(postComment, $event)"></div>
                </at>
                <!-- <base-textarea :rows="2" :max-rows="6" no-resize native :placeholder="$t('comment.type_a_comment')" v-model="newComment.body" :error.sync="formErrors.newComment" wrapper-classes="mb-0" /> -->
            </div>
            <div class="comment-footer">
                <div class="d-flex">
                    <div class="user-image-wrapper mr-2">
                        <user-avatar :user="user" :size="40" />
                    </div>
                    <base-checkbox class="ml-3 mt-2 black diff-fg-color" v-model="enterToSubmit">
                        {{ $t('general.enter_to_submit') }}
                    </base-checkbox>
                </div>

                <div class="comment-buttons">
                    <file-uploader :url="uploadURL" name-label="upload.attachment" names-label="upload.attachments" button-icon="fas fa-paperclip" button-classes="btn-sm" :button-design="btnDesign" hide-button-label hide-file-list show-selected-files-count :options="preRequisite.uploaderConfig" :data="newComment.attachments" :auto-upload="false" @selected="attachmentSelected" @uploaded="uploadedFiles" @error="uploadedFilesError" @noNeed="noNeedCallback" />

                    <base-button type="button" :design="btnDesign" size="sm" @click="postComment" class="ml-2"><i class="far fa-paper-plane"></i> {{ $t('general.submit') }}</base-button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
    import FileUploader from '@components/FileUploader'
    import { mapGetters, mapActions } from 'vuex'
    import UserAvatar from './user-avatar'
    import At from 'vue-at'
    import EventBus from '@js/event-bus'

    export default {
        name: "comments",
        components: {
            FileUploader,
            UserAvatar,
            At,
        },
        props: {
            isLoading: {
                type: Boolean,
                default: true
            },
            isDark: {
                type: Boolean,
                default: true
            },
            user: {
                type: Object,
                required: true
            },
            channel: {
                default: null
            },
            meeting: {
                type: Object,
                default () {
                    return {}
                }
            },
            members: {
                type: Array,
                default () {
                    return []
                }
            },
        },
        data() {
            return {
                uuid: null,
                isFetching: false,
                isPosting: false,
                noMoreComments: false,
                newComment: {
                    body: '',
                    attachments: [],
                    updated: false,
                },
                typingUser: null,
                typingUserTimeout: null,
                lastComment: null,
                initialNewComment: null,
                firstFetch: true,
                hasAttachment: false,
                enterToSubmit: false,
                formErrors: {},
                preRequisite: {
                    uploaderConfig: {
                        module: '',
                        token: '',
                        allowedExtensions: '',
                        maxNoOfFiles: 5,
                        uuid: uuid(),
                    },
                },
            };
        },
        computed: {
            ...mapGetters('config', [
                'vars',
                'configs',
            ]),
            ...mapGetters('common', [
                'feed',
                'filters',
            ]),
            btnDesign() {
                return this.isDark ? 'blackish' : 'white'
            },
            hasComments() {
                return this.feed.data && this.feed.data.length
            },
            uploadURL() {
                return this.lastComment ? `meetings/${this.uuid}/comments/${this.lastComment.uuid}/media` : ''
            },
        },
        methods: {
            ...mapActions('common', [
                'GetFeed',
                'PutFeedItem',
                'GetPreRequisite',
                'Custom',
                'ResetFeed',
            ]),
            attachmentSelected(count) {
                this.hasAttachment = count > 0
            },
            uploadedFiles(files) {
                this.lastComment.attachments = files
                EventBus.$emit('RESET_UPLOAD')
                this.afterUploadComplete()
            },
            uploadedFilesError(error) {
                if (error) {
                    formUtil.handleErrors(error)
                } else {
                    EventBus.$emit('RESET_UPLOAD')
                }
                this.afterUploadComplete()
            },
            noNeedCallback() {
                this.afterUploadComplete()
            },
            afterUploadComplete() {
                this.putItemToFeed(this.lastComment)
                this.isPosting = false
                this.scrollToLatest()
                this.focusNewComment()
            },
            postComment() {
                this.isPosting = true

                this.Custom({
                        url: `/meetings/${this.uuid}/comments`,
                        method: 'post',
                        data: {
                            ...this.newComment,
                            hasAttachment: this.hasAttachment,
                        }
                    })
                    .then(response => {
                        this.lastComment = response.comment
                        this.newComment = _.cloneDeep(this.initialNewComment)
                        this.$nextTick(() => {
                            EventBus.$emit('START_UPLOAD')
                        })
                    })
                    .catch(error => {
                        this.isPosting = false
                        formUtil.handleErrors(error)
                    })
            },
            showNoMoreCommentsMessage() {
                this.noMoreComments = true
                setTimeout(() => {
                    this.noMoreComments = false
                }, 4000)
            },
            fetchComments() {
                this.isFetching = true
                this.noMoreComments = false

                const query = {
                    ...this.filters,
                    apiWithAbsUrl: `meetings/${this.uuid}/comments`,
                    lastItemUuid: this.feed.meta.lastItemUuid,
                    perPage: this.feed.meta.perPage,
                }

                this.GetFeed(query)
                    .then(response => {
                        setTimeout(() => {
                            if (!response.data.length) {
                                this.showNoMoreCommentsMessage()
                            }

                            if (this.firstFetch) {
                                this.firstFetch = false
                                this.isFetching = false
                                this.scrollToLatest()
                            } else {
                                this.isFetching = false
                                this.scrollToOldest()
                            }

                            this.focusNewComment()
                        }, 1000)
                    })
                    .catch(error => {
                        this.isFetching = false
                        formUtil.handleErrors(error)
                    })
            },
            focusNewComment() {
                if(this.$refs["newCommentInput"]) {
                    this.$refs['newCommentInput'].focus()
                }
            },
            scrollToLatest() {
                if(this.$refs["vue-scroll-comments"]) {
                    this.$refs["vue-scroll-comments"].scrollTo({
                            y: "100%"
                        },
                        300
                    )
                }
            },
            scrollToOldest() {
                if(this.$refs["vue-scroll-comments"]) {
                    this.$refs["vue-scroll-comments"].scrollTo({
                            y: "0%"
                        },
                        300
                    )
                }
            },
            putItemToFeed(comment) {
                if (this.feed.data.findIndex(c => c.uuid === comment.uuid) !== -1) {
                    return
                }
                this.PutFeedItem(comment)
            },
            newCommentReceived(comment) {
                this.putItemToFeed(comment)
                this.scrollToLatest()
                this.focusNewComment()
            },
            handleScrollComplete: _.debounce(function() {
                const { scrollTop, scrollLeft } = this.$refs["vue-scroll-comments"].getPosition()
                if (scrollTop < 10) {
                    this.fetchComments()
                }
            }, 500),
            enterPressed(fnCallback, event) {
                if (this.enterToSubmit) {
                    if (!event.shiftKey) {
                        event.preventDefault()
                        if (fnCallback && typeof fnCallback === "function") {
                            fnCallback()
                        }
                    }
                }
                return false
            },
            isTyping: _.throttle(function() {
                this.channel.whisper('typing', {
                    user: this.user,
                })
            }, 500, {
                'leading': true,
                'trailing': false
            }),
            anotherUserTyping({ user }) {
                this.typingUser = user.name

                if(this.typingUserTimeout) {
                    clearTimeout(this.typingUserTimeout)
                }
                this.typingUserTimeout = setTimeout(() => {
                    this.typingUser = null
                }, 1500)
            },
        },
        mounted() {
            this.initialNewComment = _.cloneDeep(this.newComment)
            this.fetchComments()
            this.channel.listen('NewComment', this.newCommentReceived)
            this.channel.listenForWhisper('typing', this.anotherUserTyping)
            this.focusNewComment()
        },
        created() {
            if (this.$route.params.uuid) {
                this.uuid = this.$route.params.uuid
            }
            this.ResetFeed()
        },
        beforeDestroy() {
        },
    }

</script>
