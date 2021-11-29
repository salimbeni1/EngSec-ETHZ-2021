import { gql } from 'apollo-server-express';
import expect from 'expect';
import { server } from '..';
import { ICategory, IEvent, IUser, Role } from '../datamodel/db-schema';
import { dbConnect, dbDisconnect, loginAs, dbSetup } from './setup';
import { query } from './util';

describe('functional correctness', () => {
    const s = server();

    before(dbConnect);
    after(dbDisconnect);

    // Fresh database
    let database: {
        Users: { [username: string]: IUser },
        Categories: { [categoryName: string]: ICategory },
        Events: { [eventKey: string]: IEvent },
    };
    beforeEach(async () => {
        database = await dbSetup();
        await loginAs(Role.ADMINISTRATOR);
    });

    describe('creation', () => {
        it('can create categories', async () => {
            const category = 'newCategory';
            const data = await query(s, gql`mutation create($category: String!) {
                createCategory(name: $category) {
                    name
                    moderators { _id }
                    subscribers { _id }
                    events { _id }
                }
            }`, { category });
            const { name, moderators, subscribers, events } = data.createCategory;
            expect(name).toBe(category);
            for (let arr of [moderators, subscribers, events]) {
                expect(arr).toEqual([]);
            }
        })

        it('can create user', async () => {
            const user = 'newUser';
            const data = await query(s, gql`mutation create($user: String!) {
                createUser(user: {
                    username: $user,
                    name: $user,
                    surname: $user,
                    password: "",
                }) {
                    username
                }
            }`, { user });
            expect(data.createUser.username).toBe(user);
        });

        it('can create events', async () => {
            const event = {
                title: 'newEvent',
                time: new Date(),
                location: 'CAB',
                private: false,
            };
            const data = await query(s, gql`mutation create($event: CreateEvent!) {
                createEvent(event: $event) {
                    title
                    time
                    location
                    private
                }
            }`, { event });
            const { title, time, location } = data.createEvent;
            expect(title).toBe(event.title);
            expect(time).toBe(event.time);
            expect(location).toBe(event.location);
            expect(data.createEvent.private).toBeFalsy();
        });

        it('can create post and lock and clear', async () => {
            await loginAs(database.Users.fred);
            const post = {
                postedAt: database.Events.partyFred._id.toHexString(),
                content: 'grüzi wohl',
            };
            const dataPost = await query(s, gql`mutation create($post: CreatePost!) {
                createPost(post: $post) {
                    _id
                    postedAt { _id }
                    content
                }
            }`, { post });
            const { _id, postedAt, content } = dataPost.createPost;
            expect(postedAt._id).toBe(post.postedAt);
            expect(content).toBe(post.content);

            const dataFlagged = await query(s, gql`mutation flag($post: ID!) {
                flagPost(post: $post) {
                    flagged
                }
            }`, { post: _id });
            expect(dataFlagged.flagPost.flagged).toBeTruthy();

            const dataLocked = await query(s, gql`mutation lock($post: ID!) {
                review(post: $post, locked: true) {
                    flagged
                    locked
                }
            }`, { post: _id });
            const { flagged, locked } = dataLocked.review;
            expect(flagged).toBeFalsy();
            expect(locked).toBeTruthy();

            await loginAs(Role.ADMINISTRATOR);
            const dataUnlocked = await query(s, gql`mutation clear($post: ID!) {
                unlockPost(post: $post) {
                    locked
                }
            }`, { post: _id });
            expect(dataUnlocked.unlockPost.locked).toBeFalsy();
        });
    });

    describe('unification', () => {
        it('can invite and accept', async () => {
            await loginAs(database.Users.ada);
            const { fred } = database.Users;
            const user = fred._id.toHexString();
            const event = database.Events.partyPaula._id.toHexString();
            const dataInv = await query(s, gql`mutation invite($user: ID!, $event: ID!) {
                invite(user: $user, event: $event) {
                    _id
                    invited { _id }
                    to { _id }
                }
            }`, { user, event });
            const { _id, invited, to } = dataInv.invite;
            expect(invited._id).toBe(user);
            expect(to._id).toBe(event);

            await loginAs(fred);
            const dataEvent = await query(s, gql`mutation accept($inv: ID!) {
                acceptInvitation(invitation: $inv) {
                    attendants { _id }
                }
            }`, { inv: _id });
            expect(dataEvent.acceptInvitation.attendants.map(
                (attendant: { _id: String }) => attendant._id,
            )).toContain(user);
        });

        it('can request and accept', async () => {
            const { paula } = database.Users;
            await loginAs(paula);
            const event = database.Events.partyFred._id.toHexString();
            await query(s, gql`mutation request($event: ID!) {
                request(event: $event) { _id }
            }`, { event });

            await loginAs(database.Users.fred);
            const user = paula._id.toHexString();
            const data = await query (s, gql`mutation accept($user: ID!, $event: ID!) {
                acceptRequest(user: $user, event: $event) {
                    attendants { _id }
                }
            }`, { user, event });
            expect(data.acceptRequest.attendants.map(
                (attendant: { _id: String }) => attendant._id,
            )).toContain(user);
        });
    });

    describe('users', () => {
        it('can edit users', async () => {
            await loginAs(database.Users.fred);
            const edit = {
                _id: database.Users.fred._id.toHexString(),
                name: 'frank',
                surname: 'frank',
            };
            const { editUser } = await query(s, gql`mutation edit($user: EditUser!) {
                editUser(user: $user) {
                    _id
                    name
                    surname
                }
            }`, { user: edit });
            expect(editUser._id).toEqual(edit._id);
            expect(editUser.name).toEqual(edit.name);
            expect(editUser.surname).toEqual(edit.surname);
        });

        it('can delete users', async () => {
            const args = { user: database.Users.fred._id.toHexString() };
            await query(s, gql`mutation delete($user: ID!) {
                deleteUser(user: $user) { _id }
            }`, args);
            expect(query(s, gql`query get($user: ID!) {
                users(ids: [$user]) { _id }
            }`, args)).resolves.toEqual([]);
        });

        it('can query users', async () => {
            await loginAs(database.Users.fred);
            const data = await query(s, gql`query {
                usersByUsername(names: ["fred"]) {
                    role
                    username
                    name
                    surname
                    subscribes { name }
                    invitations { to { title } }
                    requests { title }
                    attends { title }
                    moderates { name }
                }
            }`);

            expect(data.usersByUsername).toHaveLength(1);
            const [user] = data.usersByUsername;
            expect(user.role).toBe(Role.FREE);
            expect(user.username).toBe('fred');
            expect(user.name).toBe('fred');
            expect(user.surname).toBe('fred');
            expect(user.subscribes).toHaveLength(2);
            expect(user.subscribes).toContainEqual({ name: 'Party' });
            expect(user.subscribes).toContainEqual({ name: 'Education' });
            expect(user.invitations).toHaveLength(0);
            expect(user.requests).toHaveLength(0);
            expect(user.attends).toHaveLength(2);
            expect(user.attends).toContainEqual({ title: 'Party of Fred' });
            expect(user.attends).toContainEqual({ title: 'Lecture of Fred' });
            expect(user.moderates).toHaveLength(0);
        });
    });
});
