import { allow, and, deny, not, or, shield } from 'graphql-shield';
import * as rules from './rules';
import { Role } from '../datamodel/db-schema';

const { callerHasRole, isCaller, Reference } = rules;

const invitedOrManager = or(
    rules.callerIsInvitedToParent,
    rules.callerManagesParent,
);

const publicOrInvitedOrAttending = or(
    not(rules.parentIsPrivate),
    rules.callerIsInvitedToParent,
    rules.callerAttendsParent,
);

const attendantUnlessLocked = and(
    rules.callerAttendsParent,
    or(not(rules.parentIsLocked), rules.callerManagesParent),
);

export const permissions = shield(
    {
        User: {
            _id: allow,
            name: rules.isLoggedIn,
            surname: rules.isLoggedIn,
            username: rules.isLoggedIn,
            role: rules.isLoggedIn,
            moderates: rules.isLoggedIn,
            attends: isCaller(Reference.PARENT),
            requests: isCaller(Reference.PARENT),
            authored: isCaller(Reference.PARENT),
            subscribes: isCaller(Reference.PARENT),
            invitations: isCaller(Reference.PARENT),
            invites: isCaller(Reference.PARENT),
        },
        Category: {
            _id: allow,
            name: allow,
            events: allow,
            moderators: rules.isLoggedIn,
            subscribers: or(
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
        },
        Invitation: {
            _id: invitedOrManager,
            from: invitedOrManager,
            invited: invitedOrManager,
            to: invitedOrManager,
        },
        Event: {
            _id: publicOrInvitedOrAttending,
            title: publicOrInvitedOrAttending,
            time: publicOrInvitedOrAttending,
            description: publicOrInvitedOrAttending,
            location: publicOrInvitedOrAttending,
            owner: publicOrInvitedOrAttending,
            private: publicOrInvitedOrAttending,
            attendants: publicOrInvitedOrAttending,
            managers: publicOrInvitedOrAttending,
            requests: rules.callerManagesParent,
            invited: rules.callerManagesParent,
            messageBoard: or(
                rules.callerAttendsParent,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
        },
        Post: {
            _id: or(
                attendantUnlessLocked,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            content: or(
                attendantUnlessLocked,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            author: or(
                attendantUnlessLocked,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            postedAt: or(
                attendantUnlessLocked,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            flagged: or(
                rules.callerManagesParent,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            locked: or(
                rules.callerManagesParent,
                rules.callerModeratesParent,
                callerHasRole(Role.ADMINISTRATOR),
            ),
        },
        Query: {
            users: rules.isLoggedIn,
            usersByUsername: rules.isLoggedIn,
            events: allow,
        },
        Mutation: {
            // Categories
            createCategory: callerHasRole(Role.ADMINISTRATOR),
            editCategory: callerHasRole(Role.ADMINISTRATOR),
            deleteCategory: callerHasRole(Role.ADMINISTRATOR),
            assignModerator: and(
                callerHasRole(Role.ADMINISTRATOR),
                rules.argHasRole(Role.MODERATOR),
            ),
            removeModerator: callerHasRole(Role.ADMINISTRATOR),

            // Users
            createUser: allow,
            login: allow,
            editUser: isCaller(Reference.ARG),
            setRole: callerHasRole(Role.ADMINISTRATOR),
            deleteUser: rules.callerHasRole(Role.ADMINISTRATOR),
            subscribe: or(
                callerHasRole(Role.PREMIUM),
                callerHasRole(Role.MODERATOR),
                callerHasRole(Role.ADMINISTRATOR),
            ),
            unsubscribe: allow,

            // Events
            createEvent: or(
                // anyone login can build a public event
                and ( 
                    rules.isLoggedIn,
                    not(rules.argIsPrivate)
                ), 
                // not free user can do whatever they want
                or(
                    callerHasRole(Role.PREMIUM),
                    callerHasRole(Role.MODERATOR),
                    callerHasRole(Role.ADMINISTRATOR),
                )
                
            ),
            editEvent: and(
                or(
                    rules.callerManagesArg,
                    or(not(rules.argOwnerDefined), not(rules.argEventHasOwner)),
                ),
                or(
                    not(rules.argIsPrivate),
                    callerHasRole(Role.PREMIUM),
                    callerHasRole(Role.MODERATOR),
                    callerHasRole(Role.ADMINISTRATOR),
                ),
            ),
            addCategories: rules.callerManagesArg,
            removeCategories: or(
                rules.callerManagesArg,
                rules.callerModeratesArg,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            deleteEvent: rules.callerOwnsParent,

            // Event management
            addAttendant: or(
                and(rules.callerManagesArg, rules.argRequestsArg),
                and(isCaller(Reference.ARG), rules.callerIsInvitedToArg),
            ),
            kick: and(
                not(and(rules.callerOwnsArg, isCaller(Reference.ARG))),
                or(isCaller(Reference.ARG), rules.callerManagesArg),
            ),
            promote: rules.callerOwnsArg,
            demote: and(rules.callerOwnsArg, not(isCaller(Reference.ARG))),

            // Invitations
            //createInvitation: rules.isLoggedIn,
            // TODO: In its current implementation, checking this permission is
            // very hard to implement - do it better!
            //editInvitation: allow,
            // NEW
            invite: or(
                rules.callerManagesArg,
                rules.callerOwnsArg,
            ),
            //deleteInvitation: or(
            //    rules.callerIsInvitedToArg,
            //    rules.callerManagesArg,
            //),
            acceptInvitation: rules.callerIsInvitedToArg,

            // Requests
            request: not(rules.argIsPrivate),
            declineRequest: or(rules.callerRequestsArg, rules.callerManagesArg),
            acceptRequest: and(rules.isLoggedIn, not(rules.argIsPrivate), rules.callerManagesArg),
            // Posts
            createPost: and(
                rules.isLoggedIn,
                rules.callerAttendsArg,
            ),
            // TODO: In its current implementation, checking this permission is
            // very hard to implement - do it better!
            // editPost: allow,
            deletePost: and(
                callerHasRole(Role.ADMINISTRATOR),
                rules.argIsLocked,
            ),
            flagPost: or(
                rules.callerAttendsArg,
                rules.callerModeratesArg,
                callerHasRole(Role.ADMINISTRATOR),
            ),
            // clearPost: or(rules.callerModeratesArg, callerHasRole(Role.ADMINISTRATOR)),
            // NEW
            review: and(
                or(
                    rules.callerModeratesArg, 
                    callerHasRole(Role.ADMINISTRATOR),
                    rules.callerManagesArg,
                ),
                rules.argIsFlagged
            ),
            unlockPost: callerHasRole(Role.ADMINISTRATOR),
        },
    },
    {
        fallbackRule: deny,
        debug: true,
    },
);
