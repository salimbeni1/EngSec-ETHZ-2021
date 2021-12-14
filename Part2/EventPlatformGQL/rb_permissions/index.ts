import { allow, and, deny, not, or, shield } from 'graphql-shield';
import * as rules from '../permissions/rules';
import { Role } from '../datamodel/db-schema';
import { OR, rbac } from './inheritance';

const { isCaller, Reference } = rules;

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

/**
 * Permissions for not being logged in.
 */
// TODO: Implement!
const DEFAULTS = {

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
            deny// callerHasRole(Role.ADMINISTRATOR),
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
            deny //callerHasRole(Role.ADMINISTRATOR),
        ),
    },

    Post: {
        _id: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
        content: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
        author: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
        postedAt: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
        flagged: or(
            rules.callerManagesParent,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
        locked: or(
            rules.callerManagesParent,
            rules.callerModeratesParent,
            deny // callerHasRole(Role.ADMINISTRATOR),
        ),
    },

    Query: {
        users: rules.isLoggedIn,
        usersByUsername: rules.isLoggedIn,
        events: allow,
    },

    Mutation: {
        // Categories
        createCategory: deny, // callerHasRole(Role.ADMINISTRATOR),
        editCategory: deny,// callerHasRole(Role.ADMINISTRATOR),
        deleteCategory: deny,//callerHasRole(Role.ADMINISTRATOR),
        assignModerator: and(
            deny,//callerHasRole(Role.ADMINISTRATOR),
            rules.argHasRole(Role.MODERATOR),
        ),
        removeModerator: deny,//callerHasRole(Role.ADMINISTRATOR),

        // Users
        createUser: allow,
        login: allow,
        editUser: isCaller(Reference.ARG),
        setRole: deny,//callerHasRole(Role.ADMINISTRATOR),
        deleteUser: deny,//rules.callerHasRole(Role.ADMINISTRATOR),
        subscribe: or(
            deny,//callerHasRole(Role.PREMIUM),
            deny,//callerHasRole(Role.MODERATOR),
            deny,//callerHasRole(Role.ADMINISTRATOR),
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
                deny,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            )
            
        ),
        editEvent: and(
            or(
                rules.callerManagesArg,
                or(not(rules.argOwnerDefined), not(rules.argEventHasOwner)),
            ),
            or(
                not(rules.argIsPrivate),
                deny,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            ),
        ),
        addCategories: rules.callerManagesArg,
        removeCategories: or(
            rules.callerManagesArg,
            rules.callerModeratesArg,
            deny,//callerHasRole(Role.ADMINISTRATOR),
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
        createInvitation: rules.isLoggedIn,
        // TODO: In its current implementation, checking this permission is
        // very hard to implement - do it better!
        editInvitation: allow,
        deleteInvitation: or(
            rules.callerIsInvitedToArg,
            rules.callerManagesArg,
        ),

        // Requests
        request: not(rules.argIsPrivate),
        removeRequest: or(rules.callerRequestsArg, rules.callerManagesArg),

        // Posts
        createPost: and(
            rules.isLoggedIn,
            rules.callerAttendsArg,
        ),
        // TODO: In its current implementation, checking this permission is
        // very hard to implement - do it better!
        editPost: allow,
        deletePost: and(
            deny,//callerHasRole(Role.ADMINISTRATOR),
            rules.argIsLocked,
        ),
        flagPost: or(
            rules.callerAttendsArg,
            rules.callerModeratesArg,
            deny,//callerHasRole(Role.ADMINISTRATOR),
        ),
        clearPost: or(
            rules.callerModeratesArg, 
            deny// callerHasRole(Role.ADMINISTRATOR)
            ),
    }
};

/**
 * Unique permissions of free users.
 */
// TODO: Implement!
const FREE = DEFAULTS;

/**
 * Unique permissions of premium users.
 */
// TODO: Implement!
const PREMIUM = {


    Mutation: {
        
        subscribe: allow,
        // Events
        createEvent: or(
            // anyone login can build a public event
            and ( 
                rules.isLoggedIn,
                not(rules.argIsPrivate)
            ), 
            // not free user can do whatever they want
            or(
                allow,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            )
            
        ),

        editEvent: and(
            or(
                rules.callerManagesArg,
                or(not(rules.argOwnerDefined), not(rules.argEventHasOwner)),
            ),
            or(
                not(rules.argIsPrivate),
                allow,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            ),
        ),
        
    }
    
};

/**
 * Unique permissions of moderators.
 */
// TODO: Implement!
const MODERATOR = {

    Mutation: {
        
        subscribe: or(
            deny,//callerHasRole(Role.PREMIUM),
            allow,//callerHasRole(Role.MODERATOR),
            deny,//callerHasRole(Role.ADMINISTRATOR),
        ),

        // Events
        createEvent: or(
            // anyone login can build a public event
            and ( 
                rules.isLoggedIn,
                not(rules.argIsPrivate)
            ), 
            // not free user can do whatever they want
            or(
                deny,//callerHasRole(Role.PREMIUM),
                allow,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            )
            
        ),
        editEvent: and(
            or(
                rules.callerManagesArg,
                or(not(rules.argOwnerDefined), not(rules.argEventHasOwner)),
            ),
            or(
                not(rules.argIsPrivate),
                deny,//callerHasRole(Role.PREMIUM),
                allow,//callerHasRole(Role.MODERATOR),
                deny,//callerHasRole(Role.ADMINISTRATOR),
            ),
        ),
        
    }



};

/**
 * Unique permissions of administrators.
 */
// TODO: Implement!
const ADMINISTRATOR = {

    Category: {
        _id: allow,
        name: allow,
        events: allow,
        moderators: rules.isLoggedIn,
        subscribers: or(
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
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
            allow //callerHasRole(Role.ADMINISTRATOR),
        ),
    },

    Post: {
        _id: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
        content: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
        author: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
        postedAt: or(
            attendantUnlessLocked,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
        flagged: or(
            rules.callerManagesParent,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
        locked: or(
            rules.callerManagesParent,
            rules.callerModeratesParent,
            allow // callerHasRole(Role.ADMINISTRATOR),
        ),
    },


    Mutation: {
        // Categories
        createCategory: allow, // callerHasRole(Role.ADMINISTRATOR),
        editCategory: allow,// callerHasRole(Role.ADMINISTRATOR),
        deleteCategory: allow,//callerHasRole(Role.ADMINISTRATOR),
        assignModerator: and(
            allow,//callerHasRole(Role.ADMINISTRATOR),
            rules.argHasRole(Role.MODERATOR),
        ),
        removeModerator: allow,//callerHasRole(Role.ADMINISTRATOR),

        
        setRole: allow,//callerHasRole(Role.ADMINISTRATOR),
        deleteUser: allow,//rules.callerHasRole(Role.ADMINISTRATOR),
        subscribe: or(
            deny,//callerHasRole(Role.PREMIUM),
            deny,//callerHasRole(Role.MODERATOR),
            allow,//callerHasRole(Role.ADMINISTRATOR),
        ),
        
        // Events
        createEvent: or(
            // anyone login can build a public event
            and ( 
                rules.isLoggedIn,
                not(rules.argIsPrivate)
            ), 
            // not free user can do whatever they want
            or(
                deny,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                allow,//callerHasRole(Role.ADMINISTRATOR),
            )
            
        ),
        editEvent: and(
            or(
                rules.callerManagesArg,
                or(not(rules.argOwnerDefined), not(rules.argEventHasOwner)),
            ),
            or(
                not(rules.argIsPrivate),
                deny,//callerHasRole(Role.PREMIUM),
                deny,//callerHasRole(Role.MODERATOR),
                allow,//callerHasRole(Role.ADMINISTRATOR),
            ),
        ),
        addCategories: rules.callerManagesArg,
        removeCategories: or(
            rules.callerManagesArg,
            rules.callerModeratesArg,
            allow,//callerHasRole(Role.ADMINISTRATOR),
        ),
        deleteEvent: rules.callerOwnsParent,

        
        
        // TODO: In its current implementation, checking this permission is
        // very hard to implement - do it better!
        editPost: allow,
        deletePost: and(
            allow,//callerHasRole(Role.ADMINISTRATOR),
            rules.argIsLocked,
        ),
        flagPost: or(
            rules.callerAttendsArg,
            rules.callerModeratesArg,
            allow,//callerHasRole(Role.ADMINISTRATOR),
        ),
        clearPost: or(
            rules.callerModeratesArg, 
            allow// callerHasRole(Role.ADMINISTRATOR)
            ),
    }

};

export const permissions = shield(
    rbac({
        [Role.FREE]: FREE,
        [Role.PREMIUM]: OR(FREE, PREMIUM),
        [Role.MODERATOR]: OR(FREE, PREMIUM, MODERATOR),
        [Role.ADMINISTRATOR]: OR(FREE, PREMIUM, MODERATOR, ADMINISTRATOR),
    }, DEFAULTS),
    {
        fallbackRule: deny,
        debug: true,
    },
);
