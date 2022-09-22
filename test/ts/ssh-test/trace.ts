//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as packageJson from './package.json';
const packageName = packageJson.name.replace(/^@\w+\//, ''); // Strip scope from name.

import * as debug from 'debug';
const trace = debug(packageName.replace('-test', ':test'));
export { trace };
