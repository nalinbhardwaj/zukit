import { ReactNode } from 'react';
import { SerializedPCD } from '@pcd/pcd-types';
import { SerializedSemaphoreGroup, SemaphoreGroupPCD } from '@pcd/semaphore-group-pcd';
import { SemaphoreSignaturePCD } from '@pcd/semaphore-signature-pcd';

interface ZupassLoginButtonProps {
    /** Default `false`. If false, requests an identity-revealing
    login. If true, requests a Semaphore proof of anonymous membership in a group. */
    anonymous?: boolean;
    /** Default `"participants"`. Also supports `"organizers"`,
    `"residents"`, and `"visitors"`. */
    namedGroup?: "participants" | "organizers" | "residents" | "visitors";
    /** Overrides `namedGroup`, specifying a semaphore group URL. For
    example, the named participants group is equivalent to passing
    `https://api.pcd-passport.com/semaphore/1`. */
    groupURL?: string;
    /** Public input signal. You can use the `generateMessageHash()`
    function from `semaphore-group-pcd` to create a signal or external nullifier
    by hashing a string. */
    signal?: bigint | string;
    /** External nullifier. This supports anonymous
    attribution. For example, you can make a poll that people can vote in
    anonymously, while ensuring that each user can only vote once. */
    externalNullifier?: bigint | string;
    /** CSS class for the button. Overrides default styling. */
    className?: string;
}
declare function ZupassLoginButton({ anonymous, namedGroup, groupURL, signal, externalNullifier, className, }: ZupassLoginButtonProps): JSX.Element;

/**
 * The Zupass server returns this data structure to users
 * to represent Zupass users.
 */
interface ZupassUserJson {
    uuid: string;
    commitment: string;
    email: string;
    salt: string | null;
    terms_agreed: number;
}

type ZupassState = {
    /** Whether the user is logged in. @see ZupassLoginButton */
    status: "logged-out" | "logged-in" | "logging-in";
} & ({
    status: "logged-out";
} | {
    status: "logging-in";
    anonymous: false;
} | {
    status: "logging-in";
    anonymous: true;
    groupURL: string;
    groupPromise: Promise<SerializedSemaphoreGroup>;
    signal: bigint;
    externalNullifier: bigint;
} | {
    status: "logged-in";
    anonymous: false;
    participant: ZupassUserJson;
    serializedPCD: SerializedPCD<SemaphoreSignaturePCD>;
    pcd: SemaphoreSignaturePCD;
} | {
    status: "logged-in";
    anonymous: true;
    groupURL: string;
    group: SerializedSemaphoreGroup;
    signal: bigint;
    externalNullifier: bigint;
    serializedPCD: SerializedPCD<SemaphoreGroupPCD>;
    pcd: SemaphoreGroupPCD;
});
type ZupassReq = {
    type: "login";
    anonymous: false;
} | {
    type: "login";
    anonymous: true;
    groupURL: string;
    signal: bigint;
    externalNullifier: bigint;
} | {
    type: "logout";
};
interface ZupassProviderProps {
    children: ReactNode;
    /** Passport API server, for loading participants and semaphore groups */
    passportServerURL?: string;
    /** Passport UI, for requesting proofs */
    passportClientURL?: string;
    /** Local app popup URL. Redirects to passport, returns resulting PCD. */
    popupURL?: string;
}

declare function ZupassProvider(props: ZupassProviderProps): JSX.Element;

declare function useZupass(): [ZupassState, (request: ZupassReq) => void];

/**
 * A react hook that sets up necessary Zupass popup logic on a specific route.
 * A popup page must be hosted on the website that integrates with Zupass, as data can't
 * be passed between a website and a popup on a different origin like zupass.org.
 * This hook sends messages with a full client-side PCD or a server-side PendingPCD
 * that can be processed by the `useZupassPopupMessages` hook. PendingPCD requests
 * can further be processed by `usePendingPCD` and `usePCDMultiplexer`.
 */
declare function useZupassPopupSetup(): string;

export { ZupassLoginButton, ZupassProvider, useZupass, useZupassPopupSetup };
