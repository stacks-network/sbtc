/**
 * @class Constants
 * @classdesc Contains useful constants for development.
 */
export class Constants {

    /**
     * Stage name used by unit tests to indicate that the resources should be
     * created for unit tests only.
     */
    static UNIT_TEST_STAGE_NAME: string = "unit-test";

    /**
     * Stage name used for stacks that are intended to only run in a local environment.
     */
    static LOCAL_STAGE_NAME: string = "local";
}
