import { and, IRules, or, rule } from 'graphql-shield';
import { LogicRule, Rule } from 'graphql-shield/dist/rules';
import { ShieldRule } from 'graphql-shield/dist/types';
import { isArray, mapValues, reduce, values } from 'lodash';
import { Role } from '../datamodel/db-schema';
import { callerHasRole, isLoggedIn } from '../permissions/rules';
import { project } from '../permissions/util';
import { mapLeafs, mergeArrayMap, RecMap } from './util';

/**
 * Type-checks `ShieldRule`
 * @param x Any value
 * @returns Is x a rule?
 */
function isRule(x: any): x is ShieldRule {
    return x instanceof Rule || x instanceof LogicRule;
}

/**
 * Merges an array of rule maps where leafs at the same path are mapped by a
 * callback.
 * @param perms Array of rule maps.
 * @param mergeLeaf Function to merge an array of leafs at the same path
 * @returns Merged rules
 */
function mergePerms(
    perms: IRules[] ,
    mergeLeaf: (leafPerms: ShieldRule[]) => ShieldRule,
): IRules {
    const arrayPerms = perms.map((perm) => mapLeafs(perm, (leaf) => [leaf], isRule));
    const merged = arrayPerms.reduce(mergeArrayMap);
    return mapLeafs(merged, mergeLeaf, isArray) as IRules;
}

/**
 * Merges an array of rule maps such that leafs at the same path are put into a
 * disjunction.
 * @param perms Array of rule maps.
 * @returns Rule map where each leafs is a disjunction
 */
export function OR(...perms: IRules[]): IRules {
    // TODO: Implement!
    /*
    return perms.reduce( (p , c) => {
        return p ; 
    } );
    */
    return mergePerms(perms , (leaf_rules) => or( ...leaf_rules));
}

/**
 * Map of user role to the role's permissions.
 */
type RBAC = { [k in Role]?: IRules };

/**
 * Merges a map of role-based access control rules into a single map of rules.
 * The resulting IRules map checks for every `[role, rules]` key-value pair
 * provided in `perms` if the user logged in as the role `role` and if so,
 * continues to check if `rules` holds. If the user has no role, the `defaults`
 * rules are applied (if present).
 * @param perms Role-based access control constraints
 * @param defaults Constraints that always hold even for users that are not
 * logged in
 * @returns Map of rules that check user roles and map it to the correct
 * permissions
 */
export function rbac(perms: RBAC, defaults: IRules): IRules {
    // TODO: Implement!
    // Array.from( perms ).map(([key, value]) => ({ key, value }));
    const TEST = Object.entries(perms).map(
        el => {
            const _role = Role[el[0] as keyof typeof Role] 
            const _rule = el[1]
            return mergePerms( [_rule] , 
                (leaf_rules) => and( callerHasRole(_role)  ,  or( ...leaf_rules))
                );
        }
        );   
    const FINAL = OR( defaults , ...TEST );
    // console.log(FINAL);
    return FINAL;
    
}
