import { Category, Event, Invitation, Post, Role, User } from '../datamodel/db-schema';
import { hash, compare } from 'bcrypt';
import { Types } from 'mongoose';
import { IContext } from '..';
import { UserInputError } from 'apollo-server-express';
import { getLoggedIn, mapIds, popId } from './util';
import { subscribes } from './User';

export interface INode {
    _id: string,
}

export interface IUserArg {
    user: string
}

export interface IEventArg {
    event: string,
}

export interface IInvitationArg {
    invitation: string,
}

export interface IPostArg {
    post: string
}

export interface ICategoryArg {
    category: string
}

export interface IEditCategory {
    name: string,
}

// TODO: Improve this resolver
export function createCategory() {
    return Category.create({});
}

export function editCategory(
    parent: undefined,
    { category }: { category: IEditCategory & INode },
) {
    const _id = popId(category);
    return Category.findOneAndUpdate({ _id }, { ...category });
}

export function deleteCategory(
    parent: undefined,
    { category }: ICategoryArg,
) {
    return Category.findByIdAndDelete(Types.ObjectId(category));
}

export function assignModerator(
    parent: undefined,
    { category, user }: ICategoryArg & IUserArg,
) {
    return Category.findByIdAndUpdate(
        Types.ObjectId(category),
        { $addToSet: Types.ObjectId(user) },
    );
}

export function removeModerator(
    parent: undefined,
    { category, user }: ICategoryArg & IUserArg,
) {
    return Category.findByIdAndUpdate(
        Types.ObjectId(category),
        { $pull: Types.ObjectId(user) },
    );
}

// TODO: Use this interface
export interface ICreateUser {
    username: string
    name: string
    surname: string
    password: string
}

const SALT_ROUNDS = 8;
// TODO: Improve this resolver
export function createUser( 
    parent: undefined,
    { user }: { user : ICreateUser} ) {
    return User.create({
        role: Role.FREE ,
        username: user.username ,
        name: user.name ,
        surname: user.surname ,
        subscribes: [] ,
        password: user.password,
    });
}

export function login(
    parent: undefined,
    { username, password }: { username: string, password: string },
    ctx: IContext,
) {
    return User.findOne({ username }).then((user) => {
        if (!user) {
            return false;
        }
        return compare(password, user.password).then((checkPassed) => {
            if (checkPassed) {
                const { username, _id, role } = user;
                ctx.session.user = { username, _id: _id.toHexString(), role };
            }
            return checkPassed;
        });
    });
}

export interface IEditUser {
    username?: string,
    name?: string,
    surname?: string,
    password?: string,
}
export function editUser(
    parent: undefined,
    { user }: { user: IEditUser & INode },
) {
    const _id = popId(user);
    if (user.password) {
        return hash(user.password, SALT_ROUNDS).then(
            (password) => User.findOneAndUpdate(
                { _id },
                { ...user, password },
            ),
        );
    } else {
        return User.findOneAndUpdate(
            { _id },
            { ...user },
        );
    }
}

export function setRole(
    parent: undefined,
    { user, role }: IUserArg & { role: Role },
) {
    return User.findByIdAndUpdate(
        Types.ObjectId(user),
        { role },
    );
}

export function deleteUser(parent: undefined, { user }: IUserArg) {
    return User.findByIdAndDelete(Types.ObjectId(user));
}

export function subscribe(
    parent: undefined,
    { categories }: { categories: string[] },
    ctx: IContext,
) {
    return User.findByIdAndUpdate(
        getLoggedIn(ctx),
        { $addToSet: { subscribes: { $each: mapIds(categories) } } },
    );
}

export function unsubscribe(
    parent: undefined,
    { categories }: { categories: string[] },
    ctx: IContext,
) {
    return User.findByIdAndUpdate(
        getLoggedIn(ctx),
        { $pull: { subscribes: { $each: mapIds(categories) } } },
    );
}

// TODO: Use this interface!
export interface ICreateEvent {
    categories?: string[],
    title: string,
    time: Date,
    description?: string,
    location: string,
    private: boolean,
}

// TODO: Improve this resolver!
export async function createEvent() {
    return Event.create({});
}

export interface IEditEvent {
    title?: string
    time?: Date
    description?: string
    location?: string
    // TODO: Remove this argument
    owner?: string
    private?: boolean
}
// TODO: Simplify this resolver
export function editEvent(
    parent: undefined,
    { event }: { event: IEditEvent & INode },
) {
    const _id = popId(event);
    const mapped: {
        owner?: Types.ObjectId,
        managers?: Types.ObjectId[],
        attendants?: Types.ObjectId[],
    } = {};
    if (event.owner) {
        const owner = Types.ObjectId(event.owner);
        mapped.owner = owner;
        mapped.managers = [owner];
        mapped.attendants = [owner];
    }
    return Event.findOneAndUpdate(
        { _id },
        // Later spreads take higher priority over earlier spread
        { ...event, ...mapped },
    );
}

export function addCategories(
    parent: undefined,
    { categories, event }: { categories: string[] } & IEventArg,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        { $addToSet: {
            categories: { $each: categories.map(Types.ObjectId) },
        } },
    )
}

export function removeCategories(
    parent: undefined,
    { categories, event }: { categories: string[] } & IEventArg,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        { $pull: {
            categories: { $in: categories.map(Types.ObjectId) },
        } },
    );
}

export function deleteEvent(
    parent: undefined,
    { event }: { event: string },
) {
    return Event.findOneAndDelete({ _id: Types.ObjectId(event) });
}

export interface IUserArg {
    user: string,
}

export function kick(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const uId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $pull: {
                attendants: uId,
                managers: uId,
            },
        },
    );
}

export function promote(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        {
            _id: Types.ObjectId(event),
            attendants: userId,
        },
        {
            $addToSet: { managers: userId },
        },
    );
}

export function demote(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $pull: { managers: userId },
        },
    );
}

// TODO: Make this resolver obsolete
export function addAttendant(parent: undefined, args: IEventArg & IUserArg) {
    return Event.findByIdAndUpdate(
        Types.ObjectId(args.event),
        { $addToSet: { attendants: Types.ObjectId(args.user) } },
    );
}

// TODO: Improve this resolver
export function createInvitation() {
    return Invitation.create({});
}

// TODO: Make this interface obsolete
export interface IEditInvitation {
    from?: string
    invited?: string
    to?: string
}
// TODO: Make this resolver obsolete
export function editInvitation(
    parent: undefined,
    { invitation }: { invitation: IEditInvitation & INode},
) {
    const _id = popId(invitation);
    const mapped: {
        from?: Types.ObjectId,
        invited?: Types.ObjectId,
        to?: Types.ObjectId,
    } = {};
    if (invitation.from) {
        mapped.from = Types.ObjectId(invitation.from);
    }
    if (invitation.invited) {
        mapped.invited = Types.ObjectId(invitation.invited);
    }
    if (invitation.to) {
        mapped.to = Types.ObjectId(invitation.to);
    }
    return Invitation.findByIdAndUpdate(_id, { ...mapped });
}

// TODO: Improve this resolver
export function deleteInvitation(
    parent: undefined,
    { invitation }: IInvitationArg,
) {
    return Invitation.findOneAndDelete({ _id: Types.ObjectId(invitation) });
}

export function request(
    parent: undefined,
    { event }: IEventArg,
    ctx: IContext,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        { $addToSet: { requests: getLoggedIn(ctx) } },
    );
}

// TODO: Improve this resolver
export function removeRequest(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        {
            _id: Types.ObjectId(event),
            requests: userId,
        },
        { $pull: { requests: userId } },
    );
}

// TODO: Use this interface
export interface ICreatePost {
    postedAt: string
    content: string
}
// TODO: Improve this resolver
export function createPost() {
    return Post.create();
}

// TODO: Make this interface obsolete
export interface IEditPost {
    content: string
    locked: boolean
    author: string
    reviewer: string
    postedAt: string
}
// TODO: Make this resolver obsolete
export function editPost(parent: undefined, { post }: { post: IEditPost & INode }) {
    const _id = popId(post);
    const mapped: {
        author?: Types.ObjectId,
        reviewer?: Types.ObjectId,
        postedAt?: Types.ObjectId,
    } = {};
    if (post.author) {
        mapped.author = Types.ObjectId(post.author);
    }
    if (post.reviewer) {
        mapped.reviewer = Types.ObjectId(post.reviewer);
    }
    if (post.postedAt) {
        mapped.postedAt = Types.ObjectId(post.postedAt);
    }
    return Post.findByIdAndUpdate(
        _id,
        // Later spreads take priority over earlier spreads
        { ...post, ...mapped },
    );
}

export function deletePost(parent: undefined, { post }: IPostArg) {
    return Post.findByIdAndDelete(Types.ObjectId(post));
}

export function flagPost(parent: undefined, { post }: IPostArg) {
    return Post.findByIdAndUpdate(
        Types.ObjectId(post),
        { flagged: true },
    );
}

// TODO: Make this resolver obsolete
export function clearPost(parent: undefined, { post }: IPostArg) {
    return Post.findByIdAndUpdate(
        Types.ObjectId(post),
        { flagged: false },
    );
}
