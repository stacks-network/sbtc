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

    /**
     * Stage name used for stacks that are intended to only run in a development environment.
     */
    static DEV_STAGE_NAME: string = "dev";

    /**
     * Stage name used for temporary stacks.
     */
    static TEMP_STAGE_NAME: string = "temp";

    /**
     * Default stage name used when no stage name is provided.
     */
    static DEFAULT_STAGE_NAME: string = "dev";

    /**
     * Default number of signer API keys to create.
     */
    static DEFAULT_NUM_SIGNER_API_KEYS: number = 3;

    /**
     * Prod stage name.
     */
    static PROD_STAGE_NAME: string = "prod";
}
