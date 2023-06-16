/**
 *
 * @param {import("frida").Device} dev
 * @returns {Promise<App[]>}
 */
export function apps(dev: import("frida").Device): Promise<App[]>;
export type App = {
    CFBundleVersion: string;
    CFBundleIdentifier: string;
    CFBundleDisplayName: number;
    CFBundleExecutable: string;
    CFBundleName: string;
    CFBundleShortVersionString: string;
    Path: string;
    Container: string;
};
export type Response = {
    Status: 'BrowsingApplications' | 'Complete';
    CurrentList: App[];
    CurrentIndex: number;
    CurrentAmount: number;
};
