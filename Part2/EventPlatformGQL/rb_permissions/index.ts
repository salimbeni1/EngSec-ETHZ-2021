import { allow, and, deny, not, or, shield } from 'graphql-shield';
import * as rules from '../permissions/rules';
import { Role } from '../datamodel/db-schema';
import { OR, rbac } from './inheritance';

const { isCaller, Reference } = rules;

/**
 * Permissions for not being logged in.
 */
// TODO: Implement!
const DEFAULTS = {};

/**
 * Unique permissions of free users.
 */
// TODO: Implement!
const FREE = {};

/**
 * Unique permissions of premium users.
 */
// TODO: Implement!
const PREMIUM = {};

/**
 * Unique permissions of moderators.
 */
// TODO: Implement!
const MODERATOR = {};

/**
 * Unique permissions of administrators.
 */
// TODO: Implement!
const ADMINISTRATOR = {};

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
