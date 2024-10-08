import AppCache from './cache';
import SchemaCache from './Adapters/Cache/SchemaCache';

/**
 * Destroys all data in the database
 * @param {boolean} fast set to true if it's ok to just drop objects and not indexes.
 */
export function destroyAllDataPermanently(fast) {
  if (!process.env.TESTING) {
    throw 'Only supported in test environment';
  }
  return Promise.all(
    Object.keys(AppCache.cache).map(appId => {
      const app = AppCache.get(appId);
      const deletePromises = [];
      if (app.cacheAdapter && app.cacheAdapter.clear) {
        deletePromises.push(app.cacheAdapter.clear());
      }
      if (app.databaseController) {
        deletePromises.push(app.databaseController.deleteEverything(fast));
      } else if (app.databaseAdapter) {
        SchemaCache.clear();
        deletePromises.push(app.databaseAdapter.deleteAllClasses(fast));
      }
      return Promise.all(deletePromises);
    })
  );
}

export function resolvingPromise() {
  let res;
  let rej;
  const promise = new Promise((resolve, reject) => {
    res = resolve;
    rej = reject;
  });
  promise.resolve = res;
  promise.reject = rej;
  return promise;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
